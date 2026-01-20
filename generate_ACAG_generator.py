from generate_ACAG_helper import GenerateACAGFunctionTools
from collections import deque
import graphviz

class ACAGSystemCreater:
    
    # 定义环境状态-攻击状态转换关系
    @staticmethod
    def cal_transition_ACAG_environment_to_attacker(current_environment_ACAG_state,
                                                    event,
                                                    event_vulnerable,
                                                    event_attacker_alterable):
        # 修正：环境状态是元组，索引 0 是预估集
        if current_environment_ACAG_state[0] == frozenset({'AX'}):
            return None
            
        # 判断事件是否可被篡改，返回一个包含所有可能篡改结果的 tuple
        events_possible = GenerateACAGFunctionTools.tamper_events(
            event_vulnerable,
            event_attacker_alterable,
            event
        )
        
        # 核心修正：使用 (tuple(events_possible),) 确保只增加了一个维度
        # 结果维度：(est_sup, est_atk, sup_s, sys_s, (e_1, e_2, ...))
        next_attacker_ACAG_state = current_environment_ACAG_state + (tuple(events_possible),)
        
        return next_attacker_ACAG_state
    @staticmethod
    def cal_transition_ACAG_attacker_to_environment(current_attacker_ACAG_state,
                                                    estimation_result_supervisor,
                                                    estimation_result_attacker,
                                                    transition_closed_loop_system,
                                                    transition_origin_system,
                                                    transition_supervisor,
                                                    event,
                                                    event_attacker_unobservable,
                                                    event_supervisor_unobservable,
                                                    tampered_event):
        # 1. 解包
        cur_est_sup, cur_est_atk, cur_sup_s, cur_sys_s, _ = current_attacker_ACAG_state
        
        # 2. 更新预估集
        #更新监督器的预估
        res_sup = GenerateACAGFunctionTools.update_unobserver_reach_supervisor(
            estimation_result_supervisor, cur_est_sup, event_supervisor_unobservable,tampered_event
        )
        # 如果为 None，说明该 tampered_event 在监督者看来是不可能的，
        next_est_sup = res_sup if res_sup is not None else frozenset({'AX'})
        #更新攻击者的预估
        next_est_atk = GenerateACAGFunctionTools.update_unobserver_reach_attacker(
            estimation_result_attacker, cur_est_atk, event_attacker_unobservable,event
        )
        
        # 3. 更新物理实态
        next_state_system = transition_origin_system.get((cur_sys_s, event))
        next_state_supervisor = transition_supervisor.get((cur_sup_s, event))
        
        # 4. 返回环境状态
        # 此时 next_est_sup 和 next_est_atk 已经是集合或 frozenset，不会再报错
        return (frozenset(next_est_sup), frozenset(next_est_atk), next_state_supervisor, next_state_system)

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
                                 transition_origin_system,
                                 transition_supervisor,
                                 state_initial_origin,
                                 state_initial_closed_loop_system,
                                 state_initial_supervisor,
                                 estimation_result_supervisor,
                                 estimation_result_attacker,
                                 secret_states
                                 ):

        environment_ACAG_states = set()
        attacker_ACAG_states = set()
        all_ACAG_transition = {}
        # 1. 初始化 Ye_0
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
        init_sup_s = list(state_initial_supervisor)[0] if isinstance(state_initial_supervisor, (set, frozenset)) else state_initial_supervisor
        init_ori_s = list(state_initial_origin)[0] if isinstance(state_initial_origin, (set, frozenset)) else state_initial_origin
        initial_env_state = (initial_est_sup, initial_est_atk, init_sup_s, init_ori_s)     
        environment_ACAG_states.add(initial_env_state)
        queue = deque([initial_env_state])     
        while queue:
            curr_env_state = queue.popleft()           
            # --- 核心逻辑修改：终止条件检查 ---          
            # 条件 1：如果监督者已报警 (AX)，停止从该状态分支
            if curr_env_state[0] == frozenset({'AX'}):
                continue
            # 条件 2：如果攻击者预估集是秘密状态集的非空子集，停止分支
            # curr_env_state[1] 是攻击者预估集 (est_atk)
            if len(curr_env_state[1]) > 0 and curr_env_state[1].issubset(secret_states):
                # 记录这是一个“终止/攻击成功”状态，但不继续探索其后继转移
                continue          
            curr_est_sup, curr_est_atk, curr_sup_s, curr_sys_s = curr_env_state
            # --- 步骤 2: Ye -> Ya ---
            for (state_in_dict, event), next_closed_state in transition_closed_loop_system.items():
                if state_in_dict == (curr_sup_s, curr_sys_s):                 
                    next_atk_state = ACAGSystemCreater.cal_transition_ACAG_environment_to_attacker(
                        curr_env_state,
                        event,
                        event_vulnerable,
                        event_attacker_alterable
                    )                   
                    if next_atk_state:
                        all_ACAG_transition[(curr_env_state, event)] = next_atk_state                      
                        if next_atk_state not in attacker_ACAG_states:
                            attacker_ACAG_states.add(next_atk_state)                           
                            # --- 步骤 3: Ya -> Ye' --
                            events_possible = next_atk_state[-1]                           
                            for tampered_event in events_possible:
                                next_env_state = ACAGSystemCreater.cal_transition_ACAG_attacker_to_environment(
                                    next_atk_state,
                                    estimation_result_supervisor,
                                    estimation_result_attacker,
                                    transition_closed_loop_system,
                                    transition_origin_system,
                                    transition_supervisor,
                                    event,
                                    event_attacker_unobservable,
                                    event_supervisor_unobservable,
                                    tampered_event
                                )

                                # 安全检查：确保 next_env_state 不为空且不重复
                                if next_env_state is not None:
                                    all_ACAG_transition[(next_atk_state, tampered_event)] = next_env_state
                                    if next_env_state not in environment_ACAG_states:
                                        environment_ACAG_states.add(next_env_state)
                                        queue.append(next_env_state)

        return all_ACAG_transition,initial_env_state

    @staticmethod
    def draw_ACAG_graph(all_ACAG_transition, initial_env_state, secret_states, filename='ACAG_DFA'):
        """
        严格遵循 ACAG 二部图定义重绘：
        - Ye (环境状态): 矩形，显示预估集和物理状态。
        - Ya (攻击状态): 黑色边框圆圈，不显示信息，作为决策分支点。
        - 颜色逻辑：SPE/暴露为橙色，报警为红色，攻击成功为绿色。
        """
        if isinstance(all_ACAG_transition, tuple):
            all_ACAG_transition = all_ACAG_transition[0]

        dot = graphviz.Digraph(comment='ACAG System', format='svg')
        # 增加间距以容纳 300+ 节点
        dot.attr(rankdir='TB', nodesep='0.5', ranksep='0.8', fontname='Arial')
        
        # 稳定的 ID 生成函数（完全基于内容，消除 hash 随机性）
        def get_id(state):
            return str(state).replace("frozenset", "").replace("set", "").replace(" ", "").translate(str.maketrans("({[]})", "      ")).replace(" ", "").replace(",", "_").replace("'", "")

        # 1. 预处理：建立邻接表并定位真正的初始状态
        adj_map = {}
        possible_nodes = set()
        for (curr, event), next_s in all_ACAG_transition.items():
            if curr not in adj_map: adj_map[curr] = []
            adj_map[curr].append((event, next_s))
            possible_nodes.add(curr)
            possible_nodes.add(next_s)

        # 寻找起点：匹配特征字符串
        real_start_node = None
        target_feat = str(initial_env_state).replace("set", "frozenset")
        for node in possible_nodes:
            if len(node) == 4 and str(node).replace("set", "frozenset") == target_feat:
                real_start_node = node
                break
        
        if not real_start_node:
            # 如果匹配不到，取字典中第一个 4 维状态作为起点
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
            if len(curr_state) == 4:  # Ye: 环境状态
                xi_S, xi_A, x, z = curr_state
                
                # 逻辑判定
                is_spe = (xi_S == 'SPE' or xi_S == frozenset({'SPE'}) or z == 'z_det')
                is_alarm = (xi_S == frozenset({'AX'}))
                is_success = (len(xi_A) > 0 and xi_A.issubset(secret_states))
                
                fill_c, color_c, pen_w = 'white', 'black', '1'
                if is_spe:
                    fill_c, color_c, pen_w = '#FFF3E0', '#E65100', '2' # 橙色：暴露/SPE
                elif is_alarm:
                    fill_c, color_c = '#FFEBEE', '#C62828' # 红色：报警
                elif is_success:
                    fill_c, color_c = '#E8F5E9', '#2E7D32' # 绿色：攻击成功

                label = f"S_Est: {set(xi_S) if not isinstance(xi_S, str) else xi_S}\nA_Est: {set(xi_A)}\nPhys: ({x}, {z})"
                dot.node(curr_id, label=label, shape='rectangle', style='filled', fillcolor=fill_c, color=color_c, penwidth=pen_w, fontsize='10')

            else:  # Ya: 攻击状态 (5元组)
                # 统一用黑色边框小圆圈代替，不显示任何文字
                dot.node(curr_id, label='', shape='circle', width='0.15', height='0.15', color='black', style='filled', fillcolor='white')

            # --- 绘制边 ---
            if curr_state in adj_map:
                for event, next_s in adj_map[curr_state]:
                    next_id = get_id(next_s)
                    
                    # 线条样式：Ye->Ya 为实线（物理事件），Ya->Ye 为虚线（篡改动作）
                    is_from_ya = (len(curr_state) == 5)
                    edge_style = 'dashed' if is_from_ya else 'solid'
                    edge_color = 'blue' if is_from_ya else 'black'
                    
                    # 如果 event 是元组或特殊标记，转为简洁字符串
                    label_str = str(event)
                    if event == 'empty': label_str = 'ε'
                    
                    dot.edge(curr_id, next_id, label=label_str, style=edge_style, color=edge_color, fontsize='9')

                    if next_s not in visited:
                        visited.add(next_s)
                        queue.append(next_s)

        # 3. 输出
        try:
            output_path = dot.render(filename, cleanup=True)
            print(f"ACAG 图表已生成：{output_path} (共 {len(visited)} 个连通节点)")
        except Exception as e:
            print(f"渲染失败，请检查是否安装了 Graphviz 软件: {e}")

        return dot