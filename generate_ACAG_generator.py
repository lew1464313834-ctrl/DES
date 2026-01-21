from generate_ACAG_helper import GenerateACAGFunctionTools
from collections import deque
import graphviz

class ACAGSystemCreater:
    
    # 定义环境状态-攻击状态转换关系
    @staticmethod
    def cal_transition_ACAG_environment_to_attacker(current_environment_ACAG_state,
                                                    event, # 原始物理事件 sigma
                                                    event_vulnerable,
                                                    event_attacker_alterable,
                                                    transition_origin_system,
                                                    estimation_result_attacker,
                                                    event_attacker_unobservable):
        '''
        Ye -> Ya 转换逻辑：
        1. 更新物理实态 x -> x'
        2. 更新攻击者预估 xi_A -> xi_A'
        3. 确定篡改选项集合 chi(sigma)
        '''
        # 解包环境状态 Ye: (xi_S, xi_A, z, x)
        cur_est_sup, cur_est_atk, cur_sup_z, cur_sys_x = current_environment_ACAG_state

        if cur_est_sup == frozenset({'AX'}):
            return None

        # 1. 更新物理实态 x' (物理系统根据原始事件演化)
        next_state_system = transition_origin_system.get((cur_sys_x, event))
        if next_state_system is None:
            return None # 物理上不可能发生的事件
        
        # 2. 更新攻击者预估 xi_A' (攻击者看到原始事件 sigma)
        next_est_atk = GenerateACAGFunctionTools.update_unobserver_reach_attacker(
            estimation_result_attacker, cur_est_atk, event_attacker_unobservable, event
        )

        # 3. 获取篡改选项
        tempered_events = GenerateACAGFunctionTools.tamper_events(
            event_vulnerable,
            event_attacker_alterable,
            event
        )

        # 返回攻击状态 Ya: (xi_S, xi_A', z, x', chi(sigma))
        # 注意：这里的 xi_S 和 z 依然是旧的，等待下一步更新
        next_attacker_ACAG_state = (cur_est_sup, frozenset(next_est_atk), cur_sup_z, next_state_system, tuple(tempered_events))
        
        return next_attacker_ACAG_state
    
    # 获取攻击状态-环境状态转换关系
    @staticmethod
    def cal_transition_ACAG_attacker_to_environment(current_attacker_ACAG_state,
                                                    estimation_result_supervisor,
                                                    transition_supervisor,
                                                    event_supervisor_unobservable,
                                                    tampered_event): # 篡改事件 sigma'
        '''
        Ya -> Ye' 转换逻辑：
        1. 仅更新监督器预估 xi_S -> xi_S'
        2. 仅更新监督器内部状态 z -> z'
        物理状态 x 和攻击者预估 xi_A 保持在上一步更新后的值
        '''
        # 1. 解包 Ya: (xi_S, xi_A_new, z, x_new, options)
        cur_est_sup, cur_est_atk, cur_sup_z, cur_sys_x, _ = current_attacker_ACAG_state
        
        # 2. 更新监督器预估 xi_S' (基于攻击者发出的 tampered_event)
        res_sup = GenerateACAGFunctionTools.update_unobserver_reach_supervisor(
            estimation_result_supervisor, cur_est_sup, event_supervisor_unobservable, tampered_event
        )
        next_est_sup = res_sup if res_sup is not None else frozenset({'AX'})
        
        # 3. 更新监督器内部状态 z' (基于攻击者发出的 tampered_event)
        if tampered_event == 'empty':
            next_state_supervisor = cur_sup_z # 擦除攻击，监督器未观测到事件，状态保持
        else:
            next_state_supervisor = transition_supervisor.get((cur_sup_z, tampered_event))
            # 如果监督器在当前 z 下不接受该事件，进入检测状态 z_det
            if next_state_supervisor is None:
                next_state_supervisor = 'z_det'
        
        # 4. 返回新的环境状态 Ye': (xi_S', xi_A_new, z', x_new)
        return (frozenset(next_est_sup), cur_est_atk, next_state_supervisor, cur_sys_x)

    #生成ACAG转移关系
    # 包括环境状态Ye（environment_ACAG_state):(监督器预估集，攻击者预估集，受控系统当前状态)
    # 攻击状态Ya(attacker_ACAG_state)
    
    @staticmethod
    def generate_ACAG_transition(
        event_attacker_unobservable,
        event_vulnerable,
        event_attacker_alterable,
        event_supervisor_unobservable,
        transition_closed_loop_system,
        transition_origin_system,      # 物理系统转移字典
        transition_supervisor,         # 监督器实现字典
        state_initial_origin,
        state_initial_closed_loop_system,
        state_initial_supervisor,
        estimation_result_supervisor,
        estimation_result_attacker,
        secret_states                  # 秘密状态集
    ):
        environment_ACAG_states = set()
        attacker_ACAG_states = set()
        all_ACAG_transition = {}

        # 1. 初始化 Ye_0 = (xi_S_0, xi_A_0, z_0, x_0)
        initial_est_sup = GenerateACAGFunctionTools.cal_unobservable_reach(
            state_initial_closed_loop_system,
            transition_closed_loop_system,
            event_supervisor_unobservable
        )
        initial_est_atk = GenerateACAGFunctionTools.cal_unobservable_reach(
            state_initial_origin,
            transition_origin_system,
            event_attacker_unobservable
        )
        
        # 获取初始实态 (物理 x0 和 监督器 z0)
        init_z = list(state_initial_supervisor)[0] if isinstance(state_initial_supervisor, (set, frozenset)) else state_initial_supervisor
        init_x = list(state_initial_origin)[0] if isinstance(state_initial_origin, (set, frozenset)) else state_initial_origin
        
        # 定义环境状态顺序：(监督器预估 xi_S, 攻击者预估 xi_A, 监督器状态 z, 物理状态 x)
        initial_env_state = (initial_est_sup, initial_est_atk, init_z, init_x)
        
        environment_ACAG_states.add(initial_env_state)
        queue = deque([initial_env_state])

        while queue:
            curr_env_state = queue.popleft()
            
            # --- 终止分支检查 ---
            # 情况 A: 监督器已报警 (xi_S = AX)
            if curr_env_state[0] == frozenset({'AX'}):
                continue
            
            # 情况 B: 攻击成功 (攻击者预估 xi_A 是秘密状态集的子集)
            if len(curr_env_state[1]) > 0 and curr_env_state[1].issubset(secret_states):
                continue

            # 解包当前环境状态 Ye
            curr_xi_S, curr_xi_A, curr_z, curr_x = curr_env_state

            # --- 步骤 2: Ye -> Ya (物理演化与攻击者观察) ---
            # 遍历物理系统在当前状态 x 下能发生的所有事件 sigma
            for (state_in_origin, sigma), next_x_in_dict in transition_origin_system.items():
                if state_in_origin == curr_x:
                    
                    # 调用修改后的 environment_to_attacker
                    # 此时已经完成了物理状态 x -> x' 和攻击者预估 xi_A -> xi_A' 的计算
                    next_atk_state = ACAGSystemCreater.cal_transition_ACAG_environment_to_attacker(
                        curr_env_state,
                        sigma,
                        event_vulnerable,
                        event_attacker_alterable,
                        transition_origin_system,
                        estimation_result_attacker,
                        event_attacker_unobservable
                    )
                    
                    if next_atk_state:
                        # 记录 Ye --sigma--> Ya
                        all_ACAG_transition[(curr_env_state, sigma)] = next_atk_state
                        
                        if next_atk_state not in attacker_ACAG_states:
                            attacker_ACAG_states.add(next_atk_state)
                            
                            # --- 步骤 3: Ya -> Ye' (攻击决策与监督器更新) ---
                            # 获取在 sigma 发生时攻击者可选择的篡改集合
                            options = next_atk_state[-1] 
                            
                            for tampered_sigma in options:
                                # 调用精简后的 attacker_to_environment
                                # 仅负责计算监督器侧的 xi_S -> xi_S' 和 z -> z'
                                next_env_state = ACAGSystemCreater.cal_transition_ACAG_attacker_to_environment(
                                    next_atk_state,
                                    estimation_result_supervisor,
                                    transition_supervisor,
                                    event_supervisor_unobservable,
                                    tampered_sigma
                                )

                                if next_env_state is not None:
                                    # 记录 Ya --tampered_sigma--> Ye'
                                    all_ACAG_transition[(next_atk_state, tampered_sigma)] = next_env_state
                                    
                                    if next_env_state not in environment_ACAG_states:
                                        environment_ACAG_states.add(next_env_state)
                                        queue.append(next_env_state)

        return all_ACAG_transition, initial_env_state

    @staticmethod
    def draw_ACAG_graph(all_ACAG_transition, 
                        initial_env_state, 
                        secret_states,
                        labled_unobservable_reachable_supervisor, # 格式: {'S0': frozenset(...)}
                        labled_unobservable_reachable_attacker,   # 格式: {'A0': frozenset(...)}
                        filename='ACAG_DFA'):
        """
        改进版 ACAG 绘图函数：
        1. 预估集显示替换为标签符号 (S0, A0...)
        2. 左上角显示标签与集合的对应关系图例
        """
        if isinstance(all_ACAG_transition, tuple):
            all_ACAG_transition = all_ACAG_transition[0]

        dot = graphviz.Digraph(comment='ACAG System', format='svg')
        # 增加间距并设置图例位置（t: top, l: left）
        dot.attr(rankdir='TB', nodesep='0.5', ranksep='0.8', fontname='Arial')
        dot.attr(labelloc='t', labeljust='l', fontsize='12')
        
        # --- 1. 构建反向映射与图例字符串 ---
        # 反向映射用于在绘图时查找标签
        sup_val_to_label = {v: k for k, v in labled_unobservable_reachable_supervisor.items()}
        atk_val_to_label = {v: k for k, v in labled_unobservable_reachable_attacker.items()}

        legend_lines = []
        legend_lines.append("Supervisor Estimates:")
        for label, s_set in sorted(labled_unobservable_reachable_supervisor.items()):
            legend_lines.append(f"  {label}: {set(s_set)}")
        
        legend_lines.append("\nAttacker Estimates:")
        for label, a_set in sorted(labled_unobservable_reachable_attacker.items()):
            legend_lines.append(f"  {label}: {set(a_set)}")
        
        # 将图例内容设置为整个图的标题
        dot.attr(label="\n".join(legend_lines))

        # 稳定的 ID 生成函数
        def get_id(state):
            return str(state).replace("frozenset", "").replace("set", "").replace(" ", "").translate(str.maketrans("({[]})", "      ")).replace(" ", "").replace(",", "_").replace("'", "")

        # 建立邻接表
        adj_map = {}
        possible_nodes = set()
        for (curr, event), next_s in all_ACAG_transition.items():
            if curr not in adj_map: adj_map[curr] = []
            adj_map[curr].append((event, next_s))
            possible_nodes.add(curr)
            possible_nodes.add(next_s)

        # 寻找起点
        real_start_node = None
        target_feat = str(initial_env_state).replace("set", "frozenset")
        for node in possible_nodes:
            if len(node) == 4 and str(node).replace("set", "frozenset") == target_feat:
                real_start_node = node
                break
        if not real_start_node:
            real_start_node = next((n for n in possible_nodes if len(n) == 4), None)

        # 2. BFS 遍历绘制
        queue = deque([real_start_node]) if real_start_node else deque()
        visited = {real_start_node} if real_start_node else set()
        
        if real_start_node:
            dot.node('start', label='', shape='none', width='0')
            dot.edge('start', get_id(real_start_node))

        while queue:
            curr_state = queue.popleft()
            curr_id = get_id(curr_state)
            
            # --- 绘制节点 ---
            if len(curr_state) == 4:  # Ye: 环境状态 (xi_S, xi_A, z, x)
                xi_S, xi_A, z, x = curr_state
                
                # 查找标签，如果找不到（如 AX 态）则显示原始简写
                s_tag = sup_val_to_label.get(xi_S, "AX" if xi_S == frozenset({'AX'}) else str(set(xi_S)))
                a_tag = atk_val_to_label.get(xi_A, str(set(xi_A)))
                
                # 逻辑判定
                is_spe = (xi_S == 'SPE' or xi_S == frozenset({'SPE'}) or z == 'z_det')
                is_alarm = (xi_S == frozenset({'AX'}))
                is_success = (len(xi_A) > 0 and xi_A.issubset(secret_states))
                
                fill_c, color_c, pen_w = 'white', 'black', '1'
                if is_spe:
                    fill_c, color_c, pen_w = '#FFF3E0', '#E65100', '2' 
                elif is_alarm:
                    fill_c, color_c = '#FFEBEE', '#C62828' 
                elif is_success:
                    fill_c, color_c = '#E8F5E9', '#2E7D32'

                # 替换后的 label 使用标签符号
                label = f" {s_tag},{a_tag},x:{x}, z:{z}"
                dot.node(curr_id, label=label, shape='rectangle', style='filled', fillcolor=fill_c, color=color_c, penwidth=pen_w, fontsize='10')

            else:  # Ya: 攻击状态 (5元组)
                dot.node(curr_id, label='', shape='circle', width='0.15', height='0.15', color='black', style='filled', fillcolor='white')

            # --- 绘制边 ---
            if curr_state in adj_map:
                for event, next_s in adj_map[curr_state]:
                    next_id = get_id(next_s)
                    is_from_ya = (len(curr_state) == 5)
                    edge_style = 'dashed' if is_from_ya else 'solid'
                    edge_color = 'blue' if is_from_ya else 'black'
                    
                    label_str = str(event)
                    if event == 'empty': label_str = 'ε'
                    
                    dot.edge(curr_id, next_id, label=label_str, style=edge_style, color=edge_color, fontsize='9')

                    if next_s not in visited:
                        visited.add(next_s)
                        queue.append(next_s)

        # 3. 输出
        try:
            output_path = dot.render(filename, cleanup=True)
            print(f"ACAG 标签化图表已生成：{output_path}")
        except Exception as e:
            print(f"渲染失败: {e}")

        return dot