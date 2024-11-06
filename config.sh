#!/system/bin/sh

# 全局配置变量
SCRIPT_DIR=$(dirname $(realpath $0))
CONFIG_FILE="${SCRIPT_DIR}/box.config"
BACKUP_DIR="${SCRIPT_DIR}/config_backup"

# 核心配置
bin_name="clash"
box_path="/data/adb/box"
run_path="${box_path}/run"
box_user_group="root:net_admin"

# 网络配置
redir_port="7891"
tproxy_port="1536"
clash_dns_port="1053"
clash_dns_listen="0.0.0.0:${clash_dns_port}"
clash_fake_ip_range="28.0.0.1/8"
proxy_method="TPROXY"
proxy_mode="blacklist"

# 订阅配置
sub_enable=false
subscribe="http://0.0.0.0"
nodes=''

# 配置验证函数
validate_config() {
    local error_count=0
    
    # 验证必要路径
    [[ -d "$box_path" ]] || { log Error "Box路径不存在: $box_path"; ((error_count++)); }
    [[ -d "$run_path" ]] || mkdir -p "$run_path"
    
    # 验证用户组设置
    if ! id -g ${box_user_group#*:} >/dev/null 2>&1; then
        log Error "无效的用户组: ${box_user_group#*:}"
        ((error_count++))
    fi
    
    # 验证端口设置
    if ! is_valid_port "$redir_port" || ! is_valid_port "$tproxy_port" || ! is_valid_port "$clash_dns_port"; then
        log Error "无效的端口配置"
        ((error_count++))
    fi
    
    # 验证代理方法
    case "$proxy_method" in
        TPROXY|REDIRECT|MIXED|APP) ;;
        *) log Error "无效的代理方法: $proxy_method"; ((error_count++)) ;;
    esac
    
    return $error_count
}

# 配置热重载
reload_config() {
    log Info "正在重新加载配置..."
    
    # 备份当前配置
    backup_config
    
    # 重新加载配置文件
    if [ -f "$CONFIG_FILE" ]; then
        source "$CONFIG_FILE"
    fi
    
    # 验证新配置
    if ! validate_config; then
        log Error "新配置验证失败，正在恢复备份..."
        restore_config
        return 1
    fi
    
    log Info "配置重载完成"
    return 0
}

# 配置备份
backup_config() {
    local backup_time=$(date +%Y%m%d_%H%M%S)
    local backup_file="${BACKUP_DIR}/config_${backup_time}.bak"
    
    mkdir -p "$BACKUP_DIR"
    cp "$CONFIG_FILE" "$backup_file"
    
    log Info "配置已备份到: $backup_file"
}

# 配置恢复
restore_config() {
    local latest_backup=$(ls -t "${BACKUP_DIR}"/*.bak 2>/dev/null | head -1)
    
    if [ -f "$latest_backup" ]; then
        cp "$latest_backup" "$CONFIG_FILE"
        log Info "已恢复配置从: $latest_backup"
        return 0
    else
        log Error "未找到配置备份"
        return 1
    fi
}

# 辅助函数：验证端口号
is_valid_port() {
    local port=$1
    [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]
}

# 导出配置变量
export_config() {
    export bin_name box_path run_path box_user_group
    export redir_port tproxy_port clash_dns_port clash_dns_listen clash_fake_ip_range
    export proxy_method proxy_mode
    export sub_enable subscribe nodes
}

# 初始化配置
init_config() {
    # 确保配置目录存在
    mkdir -p "$SCRIPT_DIR"
    
    # 如果配置文件不存在，创建默认配置
    if [ ! -f "$CONFIG_FILE" ]; then
        cat > "$CONFIG_FILE" << EOF
# Box配置文件
bin_name="$bin_name"
box_path="$box_path"
box_user_group="$box_user_group"
redir_port="$redir_port"
tproxy_port="$tproxy_port"
clash_dns_port="$clash_dns_port"
proxy_method="$proxy_method"
proxy_mode="$proxy_mode"
EOF
        log Info "已创建默认配置文件"
    fi
    
    # 加载配置文件
    source "$CONFIG_FILE"
    
    # 验证配置
    validate_config
}
