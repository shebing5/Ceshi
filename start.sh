#!/system/bin/sh

# 检查root权限
if [ "$(id -u)" -ne 0 ]; then
    echo "需要root权限运行此脚本"
    exit 1
fi

# 设置工作目录
cd "$(dirname "$0")"

# 检查必要文件
required_files=("config.sh" "core.sh" "network.sh" "utils.sh" "main.sh")
for file in "${required_files[@]}"; do
    if [ ! -f "$file" ]; then
        echo "错误: 缺少必要文件 $file"
        exit 1
    fi
done

# 设置执行权限
chmod +x ./*.sh

# 启动主程序
./main.sh "$@"
