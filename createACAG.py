import graphviz as gv
from collections import deque, defaultdict
from system_assumption import SystemAssumptions

# 初始化假设
assumption = SystemAssumptions()

# ===== 核心辅助函数（稳定版）=====
def unobservable_closure(states, transition_system, unobservable_events):
    """计算不可观闭包，返回frozenset"""
    if not states:
        return frozenset()
    closure = set(states)
    queue = deque(states)
    while queue:
        s = queue.popleft()
        for (s0, e), s1 in transition_system.items():
            if s0 == s and e in unobservable_events:
                if s1 not in closure:
                    closure.add(s1)
                    queue.append(s1)
    return frozenset(closure)

def temper_function(event, vulnerable_events, alterable_events):
    """篡改函数 - 脆弱事件可被篡改为alterable中的事件（含empty）"""
    if event in vulnerable_events:
        alternatives = set(alterable_events)
        alternatives.discard(event)  # 移除自身避免重复
        return [event] + sorted(alternatives)
    return [event]

def format_set(frozen_set):
    """将frozenset格式化为字符串"""
    if not frozen_set:
        return "∅"
    items = sorted([str(item) for item in frozen_set])
    return "{" + ", ".join(items) + "}"

# ===== 节点样式标记函数（最终修正版）=====
def get_environment_node_style(state, assumption, is_initial=False):
    """
    获取环境节点的样式和标签
    最终修正：detected = xi_A是secret的非空子集（xi_A ⊆ secret 且 xi_A ≠ ∅）
    """
    if len(state) != 4:  # 只处理环境状态
        return None, {}
    
    xi_S, xi_A, x, z = state
    base_label = f'ξ_S={format_set(xi_S)}|ξ_A={format_set(xi_A)}|x={x}, z={z}'
    
    style_dict = {'shape': 'ellipse'}
    
    # q0状态（最高优先级）
    if is_initial:
        style_dict.update({
            'style': 'bold',
            'color': 'blue',
            'penwidth': '2'
        })
        return f'{{{base_label}}}', style_dict
    
    # exposed状态：监督器预估为SPE
    if xi_S == frozenset({'SPE'}):
        style_dict.update({
            'style': 'filled',
            'fillcolor': 'grey70',
            'color': 'gray',
            'penwidth': '2'
        })
        return f'{{{base_label}}}', style_dict
    
    # detected状态：攻击者预估是secret的非空子集
    # 核心修正：xi_A ⊆ secret 且 xi_A ≠ ∅
    is_detected = (
        xi_A and  # xi_A非空
        xi_A.issubset(assumption.state_system_secret)  # xi_A是secret的子集
    )
    
    if is_detected:
        style_dict.update({
            'style': 'filled',
            'fillcolor': 'lightblue',
            'color': 'blue',
            'penwidth': '1'
        })
        return f'{{{base_label}}}', style_dict
    
    # 普通状态
    return f'{{{base_label}}}', style_dict

# ===== ACAG生成函数=====
def generate_ACAG_all_info(assumption):
    # 初始估计
    xi_S0 = unobservable_closure(
        assumption.state_initial_under_controlled_ststem,
        assumption.transition_under_controlled_system,
        assumption.event - assumption.event_supervisor_observable
    )
    xi_A0 = unobservable_closure(
        assumption.state_initial_origin_ststem,
        assumption.transition_origin_system,
        assumption.event - assumption.event_attacker_observable
    )
    
    q0 = (xi_S0, xi_A0, 
          next(iter(assumption.state_initial_origin_ststem)), 
          next(iter(assumption.state_initial_supervisor)))
    
    # 验证
    print("\n" + "="*60)
    print("事件集合验证")
    print(f"  脆弱事件: {sorted(assumption.event_vulnerable)}")
    print(f"  可篡改事件: {sorted(assumption.event_alterable)}")
    print("="*60 + "\n")
    
    # 初始化存储
    state_ACAG = {q0}
    transition_ACAG = {}
    queue = deque([q0])
    visited = set()
    active_states = {q0}
    
    # SCC计算
    graph = defaultdict(list)
    for (s, e), s_next in assumption.transition_under_controlled_system.items():
        if e != 'empty':
            graph[s].append((e, s_next))
    
    # Tarjan SCC
    index = 0
    stack, indices, lowlink, on_stack = [], {}, {}, set()
    sccs = []
    
    def strongconnect(v):
        nonlocal index
        indices[v] = lowlink[v] = index; index += 1
        stack.append(v); on_stack.add(v)
        for _, w in graph[v]:
            if w not in indices:
                strongconnect(w)
                lowlink[v] = min(lowlink[v], lowlink[w])
            elif w in on_stack:
                lowlink[v] = min(lowlink[v], indices[w])
        if lowlink[v] == indices[v]:
            scc = set()
            while True:
                w = stack.pop(); on_stack.remove(w)
                scc.add(w)
                if w == v: break
            sccs.append(scc)
    
    for v in assumption.state_under_controlled_system:
        if v not in indices:
            strongconnect(v)
    
    looping_sccs = [frozenset(scc) for scc in sccs if len(scc) > 1 or 
                    any(tgt == next(iter(scc)) for _, tgt in graph.get(next(iter(scc)), []))]
    
    # BFS主循环
    while queue:
        q = queue.popleft()
        
        if len(q) == 4:  # 环境状态 (E→A)
            xi_S, xi_A, x, z = q
            
            if q in visited:
                continue
            visited.add(q)
            
            if xi_S == frozenset({'SPE'}):
                continue
            
            for sigma in assumption.event:
                if (x, sigma) not in assumption.transition_origin_system:
                    continue
                if (z, sigma) not in assumption.transition_supervisor:
                    continue
                
                qA = (xi_S, xi_A, x, z, sigma)
                state_ACAG.add(qA)
                transition_ACAG[(q, sigma)] = qA
                active_states.add(qA)
                queue.append(qA)
        
        else:  # 攻击状态 (A→E)
            xi_S, xi_A, x, z, sigma = q
            
            if (x, sigma) not in assumption.transition_origin_system:
                continue
            
            x_next = assumption.transition_origin_system[(x, sigma)]
            
            for sigma_tilde in temper_function(sigma, assumption.event_vulnerable, 
                                              assumption.event_alterable):
                
                # 计算z'
                z_next = z
                if sigma_tilde in assumption.event_supervisor_observable:
                    if (z, sigma_tilde) in assumption.transition_supervisor:
                        z_next = assumption.transition_supervisor[(z, sigma_tilde)]
                    else:
                        z_next = 'z_det'
                
                # 计算xi_S'
                if z_next == 'z_det':
                    xi_S_next = frozenset({'SPE'})
                elif sigma_tilde in assumption.event_supervisor_observable:
                    has_transition = any(
                        (s, sigma_tilde) in assumption.transition_under_controlled_system 
                        for s in xi_S
                    )
                    
                    if not has_transition:
                        xi_S_next = frozenset({'SPE'})
                    else:
                        nx_set = {
                            assumption.transition_under_controlled_system[(s, sigma_tilde)]
                            for s in xi_S 
                            if (s, sigma_tilde) in assumption.transition_under_controlled_system
                        }
                        xi_S_next = unobservable_closure(
                            nx_set,
                            assumption.transition_under_controlled_system,
                            assumption.event - assumption.event_supervisor_observable
                        )
                else:
                    xi_S_next = xi_S
                
                # 计算xi_A'（使用原始sigma）
                if sigma in assumption.event_attacker_observable:
                    nx_set = {
                        assumption.transition_origin_system[(s, sigma)]
                        for s in xi_A 
                        if (s, sigma) in assumption.transition_origin_system
                    }
                    xi_A_next = unobservable_closure(
                        nx_set,
                        assumption.transition_origin_system,
                        assumption.event - assumption.event_attacker_observable
                    )
                else:
                    xi_A_next = xi_A
                
                # 创建新状态
                qE = (xi_S_next, xi_A_next, x_next, z_next)
                state_ACAG.add(qE)
                transition_ACAG[(q, sigma_tilde)] = qE
                active_states.add(qE)
                
                # 判断终止条件
                controlled_next_state = (x_next, z_next)
                is_terminating = (
                    xi_S_next == frozenset({'SPE'}) or
                    (xi_A_next.issubset(assumption.state_system_secret) and xi_A_next) or
                    any(controlled_next_state in scc for scc in looping_sccs)
                )
                
                if not is_terminating and qE not in visited:
                    queue.append(qE)
    
    return state_ACAG, transition_ACAG, q0, active_states

# ===== 绘图函数（完整版+特殊节点上色）=====
def draw_acag_complete(state_ACAG, transition_ACAG, q0, active_states, assumption, 
                       output_file="acag_complete.pdf"):
    """绘制ACAG图 - 显示所有转移，包括empty，特殊节点上色"""
    dot = gv.Digraph(comment='ACAG Graph - Complete')
    dot.attr(rankdir='TB')
    dot.attr('node', fontname='Arial')
    dot.attr('edge', fontname='Arial')
    
    # 为所有活跃状态创建节点
    node_id_map = {}
    node_counter = 0
    
    for state in active_states:
        node_id = f'node_{node_counter}'
        node_id_map[state] = node_id
        node_counter += 1
        
        if len(state) == 4:  # 环境状态
            # 调用样式函数获取样式（核心修正：非空子集）
            label, style_dict = get_environment_node_style(
                state, assumption, is_initial=(state == q0)
            )
            
            # 应用样式
            dot.node(node_id, label, **style_dict)
        else:  # 攻击状态
            dot.node(node_id, '', shape='point', width='0.15', height='0.15', 
                     fillcolor='black', style='filled')
    
    # 添加边（包含empty）
    drawn_edges = 0
    for (src, event), dst in transition_ACAG.items():
        if src not in node_id_map or dst not in node_id_map:
            continue
        
        style = 'solid'
        color = 'black'
        label = str(event)
        
        # 特殊标注empty转移
        if event == 'empty':
            style = 'dashed'
            color = 'gray'
            label = 'σ\'=empty\n(删除事件)'
        
        # 篡改事件标注
        elif len(src) == 5 and event != src[4]:
            style = 'dashed'
            color = 'red'
            label = f'σ\'={event}\n(篡改)'
        
        # 正常执行
        elif len(src) == 5 and event == src[4]:
            style = 'solid'
            color = 'black'
            label = f'σ\'={event}'
        
        # 意图事件
        if len(src) == 4 and len(dst) == 5:
            style = 'bold'
            color = 'blue'
            label = f'σ={event}\n(意图)'
        
        dot.edge(node_id_map[src], node_id_map[dst], label=label, style=style, color=color)
        drawn_edges += 1
    
    print(f"  活跃状态: {len(active_states)}个")
    print(f"  绘制边数: {drawn_edges}条（含empty转移）")
    dot.render(output_file, view=False, cleanup=True)
    print(f"✅ 完整版ACAG图已保存: {output_file}")

# ===== 主程序执行（最终版）=====
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