#!/system/bin/sh

# 导入配置
source "./config.sh"

# 网络相关常量定义
DEFAULT_ROUTE_TABLE="main" 
DEFAULT_MARK="0x233"
CUSTOM_ROUTE_TABLE="100"

# iptables规则管理
manage_iptables_rules() {
    local action=$1
    local chain=$2

    case $action in
        add)
            iptables -t nat -N $chain 2>/dev/null
            iptables -t mangle -N $chain 2>/dev/null
            ;;
        remove)
            iptables -t nat -F $chain 2>/dev/null
            iptables -t nat -X $chain 2>/dev/null
            iptables -t mangle -F $chain 2>/dev/null
            iptables -t mangle -X $chain 2>/dev/null
            ;;
    esac
}

# TPROXY规则设置
setup_tproxy() {
    # 创建路由表
    ip rule add fwmark $DEFAULT_MARK table $CUSTOM_ROUTE_TABLE
    ip route add local default dev lo table $CUSTOM_ROUTE_TABLE

    # 设置TPROXY规则
    manage_iptables_rules add "BOX_TPROXY"
    
    # 添加TPROXY转发规则
    iptables -t mangle -A BOX_TPROXY -p tcp -j TPROXY \
        --on-port $tproxy_port --tproxy-mark $DEFAULT_MARK
    iptables -t mangle -A BOX_TPROXY -p udp -j TPROXY \
        --on-port $tproxy_port --tproxy-mark $DEFAULT_MARK

    # 应用规则到PREROUTING链
    iptables -t mangle -A PREROUTING -j BOX_TPROXY
}

# DNS处理
setup_dns() {
    # 创建DNS链
    manage_iptables_rules add "BOX_DNS"

    # DNS转发规则
    iptables -t nat -A BOX_DNS -p udp --dport 53 -j REDIRECT --to-ports $clash_dns_port
    iptables -t nat -A BOX_DNS -p tcp --dport 53 -j REDIRECT --to-ports $clash_dns_port

    # 应用DNS规则
    iptables -t nat -A PREROUTING -j BOX_DNS
}

# FakeIP处理
setup_fakeip() {
    # 创建FakeIP链
    manage_iptables_rules add "BOX_FAKEIP"

    # FakeIP DNAT规则
    iptables -t nat -A BOX_FAKEIP -d $clash_fake_ip_range -p icmp \
        -j DNAT --to-destination 127.0.0.1

    # 应用FakeIP规则
    iptables -t nat -A PREROUTING -j BOX_FAKEIP
}

# IPv6支持
setup_ipv6() {
    if [ "$ipv6_support" = "true" ]; then
        # 启用IPv6
        sysctl -w net.ipv6.conf.all.disable_ipv6=0
        sysctl -w net.ipv6.conf.default.disable_ipv6=0

        # 设置IPv6 iptables规则
        ip6tables -t mangle -N BOX_TPROXY_V6
        ip6tables -t mangle -A BOX_TPROXY_V6 -p tcp -j TPROXY \
            --on-port $tproxy_port --tproxy-mark $DEFAULT_MARK
        ip6tables -t mangle -A BOX_TPROXY_V6 -p udp -j TPROXY \
            --on-port $tproxy_port --tproxy-mark $DEFAULT_MARK
        ip6tables -t mangle -A PREROUTING -j BOX_TPROXY_V6
    else
        # 禁用IPv6
        sysctl -w net.ipv6.conf.all.disable_ipv6=1
        sysctl -w net.ipv6.conf.default.disable_ipv6=1
    fi
}

# 网络异常恢复
network_recovery() {
    local max_retries=3
    local retry_count=0

    while [ $retry_count -lt $max_retries ]; do
        if ! ping -c 1 8.8.8.8 >/dev/null 2>&1; then
            log Warn "检测到网络异常，尝试恢复... (${retry_count}/${max_retries})"
            
            # 清理规则
            manage_iptables_rules remove "BOX_TPROXY"
            manage_iptables_rules remove "BOX_DNS"
            manage_iptables_rules remove "BOX_FAKEIP"
            
            # 重新应用规则
            setup_tproxy
            setup_dns
            setup_fakeip
            
            sleep 5
            ((retry_count++))
        else
            log Info "网络已恢复正常"
            return 0
        fi
    done
    
    log Error "网络恢复失败，请手动检查"
    return 1
}

# 初始化网络环境
init_network() {
    # 清理旧的规则
    cleanup_rules

    # 设置基础网络参数
    sysctl -w net.ipv4.ip_forward=1
    sysctl -w net.ipv4.tcp_fastopen=3
    
    # 设置连接跟踪
    sysctl -w net.netfilter.nf_conntrack_max=262144
    sysctl -w net.netfilter.nf_conntrack_tcp_timeout_established=7200
    
    # 设置网络缓冲区
    sysctl -w net.core.rmem_max=26214400
    sysctl -w net.core.wmem_max=26214400
    
    # 应用网络规则
    setup_tproxy
    setup_dns
    setup_fakeip
    setup_ipv6
    
    # 启动网络监控
    start_network_monitor
}

# 清理规则
cleanup_rules() {
    # 清理nat表规则
    manage_iptables_rules remove "BOX_DNS"
    manage_iptables_rules remove "BOX_FAKEIP"
    
    # 清理mangle表规则
    manage_iptables_rules remove "BOX_TPROXY"
    
    # 清理路由规则
    ip rule del fwmark $DEFAULT_MARK table $CUSTOM_ROUTE_TABLE 2>/dev/null
    ip route del local default dev lo table $CUSTOM_ROUTE_TABLE 2>/dev/null
}

# 启动网络监控
start_network_monitor() {
    # 在后台运行网络监控
    (while true; do
        if ! ping -c 1 8.8.8.8 >/dev/null 2>&1; then
            network_recovery
        fi
        sleep 30
    done) &

    # 记录监控进程ID
    echo $! > "${run_path}/network_monitor.pid"
    log Info "网络监控已启动"
}

# 停止网络监控
stop_network_monitor() {
    if [ -f "${run_path}/network_monitor.pid" ]; then
        kill $(cat "${run_path}/network_monitor.pid")
        rm -f "${run_path}/network_monitor.pid"
        log Info "网络监控已停止"
    fi
}

# 检查网络状态
check_network_status() {
    local status=0
    
    # 检查基本连通性
    ping -c 1 8.8.8.8 >/dev/null 2>&1 || status=$((status + 1))
    
    # 检查DNS解析
    nslookup google.com >/dev/null 2>&1 || status=$((status + 2))
    
    # 检查代理连接
    curl -x socks5://127.0.0.1:${socks_port} https://www.google.com -s >/dev/null 2>&1 || status=$((status + 4))
    
    case $status in
        0) log Info "网络状态正常" ;;
        1) log Error "基本连通性异常" ;;
        2) log Error "DNS解析异常" ;;
        4) log Error "代理连接异常" ;;
        *) log Error "多重网络异常" ;;
    esac
    
    return $status
}
