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
        '''
        获取环境状态-攻击状态转换关系
        在原环境状态下增加一个维度，表示可能的篡改事件集合
        '''
        # 修正：环境状态是元组，索引 0 是预估集
        if current_environment_ACAG_state[0] == frozenset({'AX'}):
            return None
            
        # 判断事件是否可被篡改，返回一个包含所有可能篡改结果的 tuple
        tempered_events = GenerateACAGFunctionTools.tamper_events(
            event_vulnerable,
            event_attacker_alterable,
            event
        )
        next_attacker_ACAG_state = current_environment_ACAG_state + (tuple(tempered_events),)
        
        return next_attacker_ACAG_state
    
    # 获取攻击状态-环境状态转换关系
    @staticmethod
    def cal_transition_ACAG_attacker_to_environment(current_attacker_ACAG_state,
                                                    estimation_result_supervisor,
                                                    estimation_result_attacker,
                                                    transition_origin_system,
                                                    transition_supervisor,
                                                    event, # 原始事件 sigma
                                                    event_attacker_unobservable,
                                                    event_supervisor_unobservable,
                                                    tampered_event): # 篡改事件 sigma'
        # 1. 解包：(xi_S, xi_A, z, x, options)
        cur_est_sup, cur_est_atk, cur_sup_z, cur_sys_x, _ = current_attacker_ACAG_state
        
        # 2. 更新监督器预估 (基于 tampered_event)
        res_sup = GenerateACAGFunctionTools.update_unobserver_reach_supervisor(
            estimation_result_supervisor, cur_est_sup, event_supervisor_unobservable, tampered_event
        )
        next_est_sup = res_sup if res_sup is not None else frozenset({'AX'})
        
        # 3. 更新攻击者预估 (基于 原始物理事件 event)
        next_est_atk = GenerateACAGFunctionTools.update_unobserver_reach_attacker(
            estimation_result_attacker, cur_est_atk, event_attacker_unobservable, event
        )
        
        # 4. 更新物理实态 x (始终随物理事件 event 变化)
        next_state_system = transition_origin_system.get((cur_sys_x, event))
        
        # 5. 更新监督器内部状态 z (随篡改事件 tampered_event 变化)
        if tampered_event == 'empty':
            next_state_supervisor = cur_sup_z # 擦除攻击，监督器状态不动
        else:
            next_state_supervisor = transition_supervisor.get((cur_sup_z, tampered_event))
            # 如果监督器在 z 状态下不接受 tampered_event，应进入检测状态 z_det
            if next_state_supervisor is None:
                next_state_supervisor = 'z_det'
        
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
        
        # 定义顺序：(监督器预估, 攻击者预估, 监督器状态, 物理状态)
        initial_env_state = (initial_est_sup, initial_est_atk, init_z, init_x)
        
        environment_ACAG_states.add(initial_env_state)
        queue = deque([initial_env_state])

        while queue:
            curr_env_state = queue.popleft()
            
            # --- 终止分支检查 ---
            # 情况 A: 监督器已报警
            if curr_env_state[0] == frozenset({'AX'}):
                continue
            
            # 情况 B: 攻击成功 (攻击者确信物理系统在秘密状态)
            if len(curr_env_state[1]) > 0 and curr_env_state[1].issubset(secret_states):
                # 标记该节点为成功终点，不再向下搜索
                continue

            # 严格按照初始化顺序解包
            curr_xi_S, curr_xi_A, curr_z, curr_x = curr_env_state

            # --- 步骤 2: Ye -> Ya (关键：基于物理系统 origin_system 遍历) ---
            # 只要物理系统能发生事件 sigma，攻击者就能截获
            for (state_in_origin, sigma), next_x in transition_origin_system.items():
                if state_in_origin == curr_x:
                    
                    # 生成攻击状态 Ya = (xi_S, xi_A, z, x, options)
                    next_atk_state = ACAGSystemCreater.cal_transition_ACAG_environment_to_attacker(
                        curr_env_state,
                        sigma,
                        event_vulnerable,
                        event_attacker_alterable
                    )
                    
                    if next_atk_state:
                        # 记录 Ye --sigma--> Ya
                        all_ACAG_transition[(curr_env_state, sigma)] = next_atk_state
                        
                        if next_atk_state not in attacker_ACAG_states:
                            attacker_ACAG_states.add(next_atk_state)
                            
                            # --- 步骤 3: Ya -> Ye' (针对每一个篡改决策 sigma') ---
                            options = next_atk_state[-1] # chi(sigma)
                            
                            for tampered_sigma in options:
                                next_env_state = ACAGSystemCreater.cal_transition_ACAG_attacker_to_environment(
                                    next_atk_state,
                                    estimation_result_supervisor,
                                    estimation_result_attacker,
                                    transition_origin_system,
                                    transition_supervisor,
                                    sigma,                      # 原始物理事件
                                    event_attacker_unobservable,
                                    event_supervisor_unobservable,
                                    tampered_sigma              # 篡改后的事件
                                )

                                if next_env_state is not None:
                                    # 记录 Ya --tampered_sigma--> Ye'
                                    all_ACAG_transition[(next_atk_state, tampered_sigma)] = next_env_state
                                    
                                    if next_env_state not in environment_ACAG_states:
                                        environment_ACAG_states.add(next_env_state)
                                        queue.append(next_env_state)

        return all_ACAG_transition, initial_env_state

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