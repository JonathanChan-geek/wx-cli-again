/// Windows WeChat 进程内存密钥扫描器
///
/// 使用 Windows API：
/// - CreateToolhelp32Snapshot + Process32Next: 枚举进程找 Weixin.exe
/// - OpenProcess: 获取进程句柄（需要 PROCESS_VM_READ | PROCESS_QUERY_INFORMATION）
/// - VirtualQueryEx: 枚举内存区域
/// - ReadProcessMemory: 读取内存内容
use anyhow::{Context, Result};
use std::path::Path;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT,
};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

use super::{
    collect_db_salts, collect_salt_adjacent_keys, decode_salt_hex, is_writable_readable_page,
    match_key_hexes, scan_key_patterns, KeyEntry, MAX_PATTERN_BYTES,
};

const CHUNK_SIZE: usize = 2 * 1024 * 1024;

/// 查找 Weixin.exe 进程 PID
fn find_wechat_pid() -> Option<u32> {
    // SAFETY: CreateToolhelp32Snapshot 标准 Windows API
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()? };

    let mut entry = PROCESSENTRY32 {
        dwSize: std::mem::size_of::<PROCESSENTRY32>() as u32,
        ..Default::default()
    };

    // SAFETY: Process32First/Process32Next 标准快照遍历
    unsafe {
        if Process32First(snap, &mut entry).is_err() {
            let _ = CloseHandle(snap);
            return None;
        }
        loop {
            let name =
                std::ffi::CStr::from_ptr(entry.szExeFile.as_ptr() as *const i8).to_string_lossy();
            if name.eq_ignore_ascii_case("Weixin.exe") {
                let pid = entry.th32ProcessID;
                let _ = CloseHandle(snap);
                return Some(pid);
            }
            if Process32Next(snap, &mut entry).is_err() {
                break;
            }
        }
        let _ = CloseHandle(snap);
    }
    None
}

pub fn scan_keys(db_dir: &Path) -> Result<Vec<KeyEntry>> {
    let pid = find_wechat_pid().context("找不到 Weixin.exe 进程，请确认微信正在运行")?;
    eprintln!("WeChat PID: {}", pid);

    // SAFETY: OpenProcess 请求读取权限
    let process = unsafe {
        OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid)
            .context("OpenProcess 失败，请以管理员权限运行")?
    };

    let db_salts = collect_db_salts(db_dir);
    eprintln!("找到 {} 个加密数据库", db_salts.len());

    // 收集 salt 的二进制形式，供 salt 邻接扫描使用。
    let salts: Vec<[u8; 16]> = db_salts
        .iter()
        .filter_map(|(s, _)| decode_salt_hex(s))
        .collect();

    eprintln!("扫描进程内存...");
    let (raw_keys, extra_keys) = scan_memory(process, &salts)?;
    eprintln!(
        "找到 {} 个候选密钥（字符串模式）+ {} 个 salt 邻接候选",
        raw_keys.len(),
        extra_keys.len()
    );

    // SAFETY: 关闭进程句柄
    unsafe {
        let _ = CloseHandle(process);
    }

    let entries = match_key_hexes(db_dir, &extra_keys, &raw_keys, &db_salts);
    eprintln!(
        "匹配到 {}/{} 个数据库密钥（来自 {} 个候选 key）",
        entries.len(),
        db_salts.len(),
        raw_keys.len() + extra_keys.len()
    );
    Ok(entries)
}

fn scan_memory(
    process: HANDLE,
    salts: &[[u8; 16]],
) -> Result<(Vec<(String, String)>, Vec<String>)> {
    let mut results: Vec<(String, String)> = Vec::new();
    let mut extra_keys: Vec<String> = Vec::new();
    let mut seen_extra = std::collections::HashSet::new();
    let mut addr: usize = 0;

    loop {
        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        // SAFETY: VirtualQueryEx 枚举进程内存区域
        let ret = unsafe {
            VirtualQueryEx(
                process,
                Some(addr as *const _),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if ret == 0 {
            break;
        }

        let region_size = mbi.RegionSize;
        let base = mbi.BaseAddress as usize;

        // 只扫描已提交的可读可写页面（含 WRITECOPY / EXECUTE_*WRITE*；见
        // `is_writable_readable_page`，从 old-main #54 捞回）。
        if mbi.State == MEM_COMMIT && is_writable_readable_page(mbi.Protect.0) {
            scan_region(
                process,
                base,
                region_size,
                &mut results,
                salts,
                &mut extra_keys,
                &mut seen_extra,
            );
        }

        addr = base.saturating_add(region_size);
        if addr == 0 {
            break; // overflow
        }
    }

    Ok((results, extra_keys))
}

#[allow(clippy::too_many_arguments)]
fn scan_region(
    process: HANDLE,
    base: usize,
    size: usize,
    results: &mut Vec<(String, String)>,
    salts: &[[u8; 16]],
    extra_keys: &mut Vec<String>,
    seen_extra: &mut std::collections::HashSet<String>,
) {
    let overlap = MAX_PATTERN_BYTES;
    let mut offset = 0usize;

    loop {
        if offset >= size {
            break;
        }
        let chunk_size = std::cmp::min(CHUNK_SIZE, size - offset);
        let addr = base + offset;
        let mut buf = vec![0u8; chunk_size];
        let mut bytes_read: usize = 0;

        // SAFETY: ReadProcessMemory 读取目标进程内存
        let ok = unsafe {
            ReadProcessMemory(
                process,
                addr as *const _,
                buf.as_mut_ptr() as *mut _,
                chunk_size,
                Some(&mut bytes_read),
            )
            .is_ok()
        };

        if ok && bytes_read > 0 {
            buf.truncate(bytes_read);
            search_pattern(&buf, results);
            // 微信 4.x 的 key 常常只以「key || salt」二进制形式存在堆上，
            // 不一定是 x'<hex>' 字符串；补一条 salt 邻接扫描路径。
            collect_salt_adjacent_keys(&buf, salts, extra_keys, seen_extra);
        }

        if chunk_size > overlap {
            offset += chunk_size - overlap;
        } else {
            offset += chunk_size;
        }
    }
}

fn search_pattern(buf: &[u8], results: &mut Vec<(String, String)>) {
    scan_key_patterns(buf, results);
}
