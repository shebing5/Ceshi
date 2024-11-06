#!/system/bin/sh

# 导入配置
source "./config.sh"

# 日志级别定义
declare -A LOG_LEVELS=(['DEBUG']=0 ['INFO']=1 ['WARN']=2 ['ERROR']=3)
CURRENT_LOG_LEVEL=${LOG_LEVELS['INFO']}

# 日志函数
log() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # 检查日志级别
    if [ ${LOG_LEVELS[$level]} -ge $CURRENT_LOG_LEVEL ]; then
        case $level in
            'DEBUG') local color="\033[1;34m" ;;
            'INFO')  local color="\033[1;32m" ;;
            'WARN')  local color="\033[1;33m" ;;
            'ERROR') local color="\033[1;31m" ;;
            *)       local color="\033[0m" ;;
        esac
        
        # 输出日志
        if [ -t 1 ]; then
            echo -e "${color}[${timestamp}] [${level}] ${message}\033[0m"
        else
            echo "[${timestamp}] [${level}] ${message}"
        fi
        
        # 记录到文件
        echo "[${timestamp}] [${level}] ${message}" >> "${run_path}/box.log"
    fi
}

# 错误处理函数
handle_error() {
    local error_code=$1
    local error_message=$2
    
    log ERROR "错误发生: $error_message (代码: $error_code)"
    
    # 发送错误通知
    send_notification "错误" "$error_message"
    
    # 记录错误堆栈
    print_stack_trace
    
    # 根据错误代码执行不同的恢复操作
    case $error_code in
        1) # 配置错误
            log WARN "尝试恢复配置..."
            restore_config
            ;;
        2) # 网络错误
            log WARN "尝试恢复网络..."
            network_recovery
            ;;
        3) # 进程错误
            log WARN "尝试重启服务..."
            restart_core_service
            ;;
        *) # 其他错误
            log ERROR "未知错误，无法自动恢复"
            return 1
            ;;
    esac
}

# 打印堆栈跟踪
print_stack_trace() {
    local frame=0
    while caller $frame; do
        ((frame++))
    done | awk '{ print "[堆栈] 在 " $3 " 函数的第 " $1 " 行 (" $2 ")" }' >> "${run_path}/error.log"
}

# 发送通知
send_notification() {
    local title=$1
    local message=$2
    
    # 如果存在通知脚本则执行
    if [ -x "${box_path}/scripts/notify.sh" ]; then
        "${box_path}/scripts/notify.sh" "$title" "$message"
    fi
}

# 检查系统资源
check_system_resources() {
    # 检查CPU使用率
    local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d. -f1)
    if [ "$cpu_usage" -gt 80 ]; then
        log WARN "CPU使用率过高: ${cpu_usage}%"
        return 1
    fi
    
    # 检查内存使用
    local mem_free=$(free -m | awk '/^Mem:/{print $4}')
    if [ "$mem_free" -lt 100 ]; then
        log WARN "可用内存不足: ${mem_free}MB"
        return 2
    fi
    
    # 检查磁盘空间
    local disk_usage=$(df -h "${box_path}" | awk 'NR==2 {print $5}' | cut -d% -f1)
    if [ "$disk_usage" -gt 90 ]; then
        log WARN "磁盘空间不足: ${disk_usage}%"
        return 3
    fi
    
    return 0
}

# 清理日志文件
clean_logs() {
    local max_size=10485760  # 10MB
    local log_file="${run_path}/box.log"
    
    if [ -f "$log_file" ]; then
        local file_size=$(stat -f%z "$log_file")
        if [ "$file_size" -gt "$max_size" ]; then
            local timestamp=$(date +%Y%m%d_%H%M%S)
            mv "$log_file" "${log_file}.${timestamp}"
            gzip "${log_file}.${timestamp}"
            touch "$log_file"
            log INFO "日志文件已归档: ${log_file}.${timestamp}.gz"
        fi
    fi
}

# 检查更新
check_update() {
    local current_version=$(get_version)
    local latest_version=$(fetch_latest_version)
    
    if [ "$current_version" != "$latest_version" ]; then
        log INFO "发现新版本: $latest_version"
        send_notification "更新可用" "新版本 $latest_version 可用"
        return 0
    fi
    return 1
}

# 获取当前版本
get_version() {
    if [ -f "${box_path}/version" ]; then
        cat "${box_path}/version"
    else
        echo "unknown"
    fi
}

# 获取最新版本
fetch_latest_version() {
    # 实际应用中需要实现从服务器获取版本的逻辑
    echo "1.0.0"
}

# 文件锁操作
acquire_lock() {
    local lock_file="${run_path}/box.lock"
    
    if mkdir "$lock_file" 2>/dev/null; then
        trap 'rm -rf "$lock_file"' EXIT
        return 0
    fi
    return 1
}

release_lock() {
    local lock_file="${run_path}/box.lock"
    rm -rf "$lock_file"
}

# 判断程序是否在运行
is_running() {
    local pid_file="${run_path}/${1:-$bin_name}.pid"
    
    if [ -f "$pid_file" ]; then
        local pid=$(cat "$pid_file")
        if kill -0 "$pid" 2>/dev/null; then
            return 0
        fi
    fi
    return 1
}

# 等待程序退出
wait_for_exit() {
    local pid=$1
    local timeout=${2:-30}
    local count=0
    
    while [ $count -lt $timeout ]; do
        if ! kill -0 "$pid" 2>/dev/null; then
            return 0
        fi
        sleep 1
        ((count++))
    done
    
    return 1
}

# 生成随机字符串
generate_random_string() {
    local length=${1:-16}
    tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c "$length"
}

# 运行时间统计
get_uptime() {
    local pid_file="${run_path}/${bin_name}.pid"
    if [ -f "$pid_file" ]; then
        local pid=$(cat "$pid_file")
        if [ -d "/proc/$pid" ]; then
            local start_time=$(stat -c %Y "/proc/$pid")
            local current_time=$(date +%s)
            local uptime=$((current_time - start_time))
            
            # 格式化输出
            local days=$((uptime/86400))
            local hours=$(((uptime%86400)/3600))
            local minutes=$(((uptime%3600)/60))
            local seconds=$((uptime%60))
            
            echo "${days}天 ${hours}小时 ${minutes}分钟 ${seconds}秒"
            return 0
        fi
    fi
    echo "未运行"
    return 1
}

# 导出所有函数
export -f log
export -f handle_error
export -f check_system_resources
export -f clean_logs
export -f check_update
export -f is_running
export -f get_uptime
export -f generate_random_string
