#!/system/bin/sh

# 导入配置和工具函数
source "./config.sh"
source "./utils.sh"

# 核心功能常量
MAX_RETRIES=3
RESTART_DELAY=5

# 启动核心服务
start_core_service() {
    local retry_count=0
    
    # 检查权限
    check_service_permissions || return 1
    
    # 初始化环境
    init_core_environment || return 1
    
    while [ $retry_count -lt $MAX_RETRIES ]; do
        log Info "正在启动 ${bin_name} 核心服务..."
        
        # 启动核心进程
        if launch_core_process; then
            # 等待服务启动
            if wait_for_core_ready; then
                log Info "${bin_name} 核心服务启动成功"
                monitor_core_service &
                return 0
            fi
        fi
        
        ((retry_count++))
        log Warn "启动失败，重试 ($retry_count/$MAX_RETRIES)..."
        sleep $RESTART_DELAY
    done
    
    log Error "${bin_name} 核心服务启动失败"
    return 1
}

# 停止核心服务
stop_core_service() {
    log Info "正在停止 ${bin_name} 核心服务..."
    
    # 停止监控
    stop_core_monitor
    
    # 获取进程ID
    local pid=$(get_core_pid)
    
    if [ -n "$pid" ]; then
        # 发送终止信号
        kill $pid
        
        # 等待进程结束
        wait_for_core_stop $pid
        
        # 清理资源
        cleanup_core_resources
        
        log Info "${bin_name} 核心服务已停止"
        return 0
    else
        log Warn "${bin_name} 核心服务未运行"
        return 1
    fi
}

# 重启核心服务
restart_core_service() {
    log Info "正在重启 ${bin_name} 核心服务..."
    stop_core_service
    sleep $RESTART_DELAY
    start_core_service
}

# 检查核心服务状态
check_core_status() {
    local pid=$(get_core_pid)
    
    if [ -n "$pid" ]; then
        # 检查进程状态
        if check_process_status $pid; then
            # 检查服务是否正常响应
            if check_core_response; then
                log Info "${bin_name} 核心服务运行正常 (PID: $pid)"
                return 0
            else
                log Warn "${bin_name} 核心服务无响应"
                return 2
            fi
        fi
    fi
    
    log Error "${bin_name} 核心服务未运行"
    return 1
}

# 监控核心服务
monitor_core_service() {
    while true; do
        sleep 30
        
        if ! check_core_status; then
            log Warn "检测到服务异常，尝试恢复..."
            restart_core_service
        fi
        
        # 检查资源使用
        check_resource_usage
        
        # 检查连接状态
        check_connection_status
    done
}

# 初始化核心环境
init_core_environment() {
    # 创建必要目录
    mkdir -p "${run_path}"
    mkdir -p "${box_path}/logs"
    
    # 设置权限
    chown -R ${box_user_group} "${box_path}"
    chmod -R 755 "${box_path}"
    
    # 优化系统参数
    optimize_system_params
    
    # 初始化核心配置
    generate_core_config
    
    return 0
}

# 启动核心进程
launch_core_process() {
    # 设置进程限制
    ulimit -SHn 1000000
    
    # 启动进程
    case "${bin_name}" in
        clash)
            nohup ${bin_path} -d ${box_path} -f ${box_path}/config.yaml \
                > ${box_path}/logs/clash.log 2>&1 &
            ;;
        xray)
            nohup ${bin_path} -config ${box_path}/config.json \
                > ${box_path}/logs/xray.log 2>&1 &
            ;;
        *)
            log Error "不支持的核心类型: ${bin_name}"
            return 1
            ;;
    esac
    
    # 保存PID
    echo $! > "${run_path}/${bin_name}.pid"
    return 0
}

# 检查服务权限
check_service_permissions() {
    # 检查运行用户
    if [ "$(id -u)" -ne 0 ]; then
        log Error "需要root权限"
        return 1
    fi
    
    # 检查二进制文件
    if [ ! -x "${bin_path}" ]; then
        log Error "核心程序不存在或没有执行权限: ${bin_path}"
        return 1
    fi
    
    return 0
}

# 等待核心就绪
wait_for_core_ready() {
    local timeout=30
    local count=0
    
    while [ $count -lt $timeout ]; do
        if check_core_response; then
            return 0
        fi
        sleep 1
        ((count++))
    done
    
    return 1
}

# 获取核心PID
get_core_pid() {
    if [ -f "${run_path}/${bin_name}.pid" ]; then
        cat "${run_path}/${bin_name}.pid"
    fi
}

# 检查进程状态
check_process_status() {
    local pid=$1
    kill -0 $pid 2>/dev/null
}

# 检查核心响应
check_core_response() {
    case "${bin_name}" in
        clash)
            curl -s "http://127.0.0.1:9090/status" >/dev/null
            return $?
            ;;
        xray)
            # 根据实际情况实现检查逻辑
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

# 等待进程停止
wait_for_core_stop() {
    local pid=$1
    local timeout=30
    local count=0
    
    while [ $count -lt $timeout ]; do
        if ! check_process_status($pid); then
            return 0
        fi
        sleep 1
        ((count++))
    done
    
    # 强制终止
    kill -9 $pid 2>/dev/null
    return 1
}

# 清理核心资源
cleanup_core_resources() {
    # 清理PID文件
    rm -f "${run_path}/${bin_name}.pid"
    
    # 清理临时文件
    rm -f "${run_path}"/*.tmp
    
    # 归档日志
    archive_logs
}

# 检查资源使用
check_resource_usage() {
    local pid=$(get_core_pid)
    if [ -n "$pid" ]; then
        # 检查CPU使用率
        local cpu_usage=$(ps -p $pid -o %cpu | tail -n1)
        if [ $(echo "$cpu_usage > 80" | bc) -eq 1 ]; then
            log Warn "CPU使用率过高: ${cpu_usage}%"
        fi
        
        # 检查内存使用
        local mem_usage=$(ps -p $pid -o %mem | tail -n1)
        if [ $(echo "$mem_usage > 70" | bc) -eq 1 ]; then
            log Warn "内存使用率过高: ${mem_usage}%"
        fi
    fi
}

# 优化系统参数
optimize_system_params() {
    # 设置系统参数
    sysctl -w net.ipv4.ip_forward=1
    sysctl -w net.ipv4.tcp_fastopen=3
    sysctl -w fs.file-max=1000000
    
    # 优化内核参数
    sysctl -w net.core.rmem_max=26214400
    sysctl -w net.core.wmem_max=26214400
    sysctl -w net.ipv4.tcp_rmem="4096 87380 67108864"
    sysctl -w net.ipv4.tcp_wmem="4096 65536 67108864"
}

# 生成核心配置
generate_core_config() {
    case "${bin_name}" in
        clash)
            # 生成Clash配置
            generate_clash_config
            ;;
        xray)
            # 生成Xray配置
            generate_xray_config
            ;;
    esac
}

# 归档日志
archive_logs() {
    local date_suffix=$(date +%Y%m%d_%H%M%S)
    local log_file="${box_path}/logs/${bin_name}.log"
    
    if [ -f "$log_file" ]; then
        mv "$log_file" "${log_file}.${date_suffix}"
        gzip "${log_file}.${date_suffix}"
    fi
}

# 导出函数
export -f start_core_service
export -f stop_core_service
export -f restart_core_service
export -f check_core_status
