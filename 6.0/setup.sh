#!/usr/bin/env bash
set -e

echo "========================================"
echo "  用户管理系统（安全加固版）"
echo "  环境配置 - Kali Linux"
echo "========================================"

MISSING=""

echo "🔍 检查 Python 依赖..."

for pkg in python3-flask python3-flaskext.wtf python3-flask-limiter python3-werkzeug; do
    if dpkg -l "$pkg" &>/dev/null 2>&1; then
        echo "  ✅ $pkg 已安装"
    else
        echo "  ❌ $pkg 未安装"
        MISSING="$MISSING $pkg"
    fi
done

if [ -n "$MISSING" ]; then
    echo ""
    echo "📦 正在安装缺失的依赖..."
    sudo apt update -qq
    sudo apt install -y $MISSING
    echo "✅ 依赖安装完成"
else
    echo ""
    echo "✅ 所有依赖已就绪"
fi

echo ""
echo "========================================"
echo "  环境就绪！启动方式："
echo "  python3 app.py"
echo "========================================"
