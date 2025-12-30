import dataclasses
from typing import Set, Dict, Any
from createACAG import generate_ACAG_all_info, draw_acag_complete
from system_assumption import SystemAssumptions
# ===== 主程序执行=====
if __name__ == "__main__":
    print("\n" + "="*60)
    print("ACAG生成程序 - 最终完美版（detected判断是否空子集）")
    print("="*60 + "\n")
    
    # 生成ACAG
    print("[阶段1/3] 生成ACAG...")
    state_ACAG, transition_ACAG, q0, active_states = generate_ACAG_all_info(assumption)
    print(f"✓ 总状态数: {len(state_ACAG)}")
    print(f"✓ 活跃状态数: {len(active_states)}")
    print(f"✓ 转移数: {len(transition_ACAG)}")
    
    # 统计特殊状态
    exposed_count = 0
    detected_count = 0
    for state in active_states:
        if len(state) == 4:
            xi_S, xi_A, x, z = state
            if xi_S == frozenset({'SPE'}):
                exposed_count += 1
            elif xi_A and xi_A.issubset(assumption.state_system_secret):
                detected_count += 1
    
    print(f"  exposed状态: {exposed_count}个（灰色）")
    print(f"  detected状态: {detected_count}个（蓝色，非空子集）")
    
    # 审计o3→o1
    print("\n[阶段2/3] 审计o3→o1转移...")
    violations = 0
    for (src, event), dst in transition_ACAG.items():
        if len(src) == 5 and src[4] == 'o3' and event == 'o1':
            violations += 1
            print(f"❌ 发现违规: {src} --{event}--> {dst}")
    
    if violations == 0:
        print("✅ 审计通过：无o3→o1违规")
    else:
        print(f"❌ 发现 {violations} 条o3→o1违规！")
        exit(1)
    
    # 绘图
    print("\n[阶段3/3] 绘制完整图（含特殊节点上色）...")
    draw_acag_complete(state_ACAG, transition_ACAG, q0, active_states, assumption, 
                      "acag")
    
    print("\n" + "="*60)
    print("✅ ACAG生成完成！")
    print("="*60)
    print("特性：")
    print("  ✓ 无o3o1违规")
    print("  ✓ 保留empty转移")
    print("  ✓ detected判断：非空子集（xi_A ⊆ secret 且 xi_A ≠ ∅）")
    print("  ✓ exposed节点：灰色填充")
    print("  ✓ detected节点：蓝色填充")
    print("="*60 + "\n")