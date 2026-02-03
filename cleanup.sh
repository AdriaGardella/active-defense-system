#!/bin/bash
# =====================================================
# Active Defense System — Cleanup
# Resetea el firewall y archivos temporales generados
# Ejecutar en la VM Ubuntu con: bash cleanup.sh
# =====================================================

echo "=========================================="
echo "  Active Defense System - Cleanup"
echo "=========================================="
echo ""

# 1. Mostrar reglas actuales antes de limpiar
echo "[*] Reglas de iptables actuales:"
sudo iptables -L INPUT -v -n --line-numbers
echo ""

# 2. Limpiar todas las reglas de INPUT
echo "[1/3] Limpiando reglas de iptables..."
sudo iptables -F INPUT
echo "  ✓ Reglas eliminadas"

# 3. Eliminar archivo de IPs bloqueadas
echo "[2/3] Eliminando blocked_ips.txt..."
rm -f blocked_ips.txt
echo "  ✓ Archivo eliminado"

# 4. Eliminar base de datos (opcional)
echo "[3/3] Base de datos (defense_log.db)..."
if [ -f "defense_log.db" ]; then
    read -p "  ¿Deseas eliminar la base de datos? (s/N): " respuesta
    if [[ "$respuesta" =~ ^[Ss]$ ]]; then
        rm -f defense_log.db
        echo "  ✓ Base de datos eliminada"
    else
        echo "  ⏭ Base de datos conservada"
    fi
else
    echo "  ⏭ No existe base de datos"
fi

echo ""
echo "=========================================="
echo "  ✓ Cleanup completado"
echo "=========================================="
echo ""
echo "  El sistema queda listo para volver a ejecutar:"
echo "  python3 active_defense.py"
echo ""