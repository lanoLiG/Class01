#!/usr/bin/env bash
set -e

echo "========================================"
echo "  用户管理系统 - 环境检查"
echo "========================================"

if python3 -c "import flask" &>/dev/null; then
    echo "✅ Flask 已就绪"
else
    echo "📦 正在安装 Flask..."
    sudo apt update -qq && sudo apt install -y python3-flask
    echo "✅ Flask 安装完成"
fi

echo ""
echo "========================================"
echo "  环境就绪！启动方式："
echo "  python3 app.py"
echo "========================================"
