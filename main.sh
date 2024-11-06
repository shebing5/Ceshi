#!/system/bin/sh

# 导入所需模块
source "./config.sh"
source "./core.sh"
source "./network.sh"
source "./utils.sh"

# 全局常量定义
VERSION="1.0.0"
LOCK_FILE="${run_path}/box.lock"

# 主函数
main() {
    # 检查是否已经运行
    if [ -f "$LOCK_FILE" ]; then
        log Error "程序已在运行中"
        exit 1
    fi

    # 创建锁文件
    acquire_lock || exit 1
    trap 'cleanup; exit' INT TERM

    # 初始化配置
    log Info "正在初始化配置..."
    init_config || exit 1

    # 根据命令行参数执行操作
    case "$1" in
        start)
            start_program
            ;;
        stop)
            stop_program
            ;;
        restart)
            restart_program
            ;;
        status)
            show_status
            ;;
        update)
            update_program
            ;;
        clean)
            clean_program
            ;;
        *)
            show_usage
            ;;
    esac

    # 释放锁
    release_lock
}

# 启动程序
start_program() {
    log Info "正在启动服务..."
    
    # 初始化环境
    init_environment || {
        log Error "环境初始化失败"
        return 1
    }
    
    # 启动核心服务
    start_core_service || {
        log Error "核心服务启动失败"
        return 1
    }
    
    # 初始化网络
    init_network || {
        log Error "网络初始化失败"
        stop_core_service
        return 1
    }
    
    # 启动监控服务
    start_monitoring
    
    log Info "服务启动完成"
}

# 停止程序
stop_program() {
    log Info "正在停止服务..."
    
    # 停止监控
    stop_monitoring
    
    # 停止网络服务
    cleanup_network || log Warn "网络清理失败"
    
    # 停止核心服务
    stop_core_service || log Warn "核心服务停止失败"
    
    log Info "服务已停止"
}

# 重启程序
restart_program() {
    log Info "正在重启服务..."
    stop_program
    sleep 2
    start_program
}

# 显示状态
show_status() {
    log Info "程序版本: $VERSION"
    
    # 检查核心服务状态
    check_core_status
    
    # 检查网络状态
    check_network_status
    
    # 显示资源使用情况
    show_resource_usage
    
    # 显示运行时间
    show_uptime
}

# 更新程序
update_program() {
    log Info "检查更新..."
    
    # 检查新版本
    if check_update; then
        # 备份当前配置
        backup_config
        
        # 下载并安装更新
        download_update || {
            log Error "更新下载失败"
            return 1
        }
        
        # 安装更新
        install_update || {
            log Error "更新安装失败"
            return 1
        }
        
        # 重启服务
        restart_program
        
        log Info "更新完成"
    else
        log Info "已是最新版本"
    fi
}

# 清理程序
clean_program() {
    log Info "开始清理..."
    
    # 停止服务
    stop_program
    
    # 清理日志
    clean_logs
    
    # 清理缓存
    clean_cache
    
    # 清理临时文件
    clean_temp_files
    
    log Info "清理完成"
}

# 初始化环境
init_environment() {
    # 创建必要目录
    mkdir -p "${run_path}"
    mkdir -p "${box_path}/logs"
    mkdir -p "${box_path}/cache"
    
    # 设置文件权限
    chmod -R 755 "${box_path}"
    chown -R ${box_user_group} "${box_path}"
    
    # 优化系统参数
    optimize_system_params
    
    return 0
}

# 启动监控
start_monitoring() {
    # 启动资源监控
    (while true; do
        check_system_resources
        sleep 300
    done) &
    echo $! > "${run_path}/monitor_resources.pid"
    
    # 启动网络监控
    start_network_monitor
    
    log Info "监控服务已启动"
}

# 停止监控
stop_monitoring() {
    # 停止资源监控
    if [ -f "${run_path}/monitor_resources.pid" ]; then
        kill $(cat "${run_path}/monitor_resources.pid")
        rm -f "${run_path}/monitor_resources.pid"
    fi
    
    # 停止网络监控
    stop_network_monitor
    
    log Info "监控服务已停止"
}

# 清理网络设置
cleanup_network() {
    # 清理防火墙规则
    cleanup_rules
    
    # 恢复系统网络设置
    sysctl -w net.ipv4.ip_forward=0
    
    # 启用IPv6
    enable_ipv6
    
    return 0
}

# 显示资源使用情况
show_resource_usage() {
    local pid=$(get_core_pid)
    if [ -n "$pid" ]; then
        echo "CPU使用率: $(ps -p $pid -o %cpu | tail -n1)%"
        echo "内存使用: $(ps -p $pid -o %mem | tail -n1)%"
        echo "打开文件数: $(ls -l /proc/$pid/fd | wc -l)"
    fi
}

# 显示运行时间
show_uptime() {
    local uptime=$(get_uptime)
    echo "运行时间: $uptime"
}

# 显示使用帮助
show_usage() {
    echo "用法: $0 {start|stop|restart|status|update|clean}"
    echo "  start   - 启动服务"
    echo "  stop    - 停止服务"
    echo "  restart - 重启服务"
    echo "  status  - 显示状态"
    echo "  update  - 检查更新"
    echo "  clean   - 清理系统"
}

# 清理函数
cleanup() {
    # 释放锁
    release_lock
    
    # 停止所有服务
    stop_program
    
    # 删除PID文件
    rm -f "${run_path}"/*.pid
}

# 程序入口
main "$@"
