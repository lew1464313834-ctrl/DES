from .generate_ACAG_helper import GenerateACAGFunctionTools
from collections import deque
import graphviz

class ACAGSystemCreater:
    
    # 定义环境状态-攻击状态转换关系
    @staticmethod
    def cal_transition_ACAG_environment_to_attacker(current_environment_ACAG_state,
                                                    event, # 原始物理事件 sigma
                                                    event_vulnerable,
                                                    event_attacker_alterable,
                                                    transition_supervisor,
                                                    transition_origin_system):
        '''
        Ye -> Ya 转换逻辑：
        【修改点】：此处不再更新攻击者预估 xi_A，而是将原始事件 sigma 和旧的 xi_A 传递给 Ya 节点。
        '''
        # 解包环境状态 Ye: (xi_S, xi_A, z, x)
        cur_est_sup, cur_est_atk, cur_sup_z, cur_sys_x = current_environment_ACAG_state

        if cur_est_sup == frozenset({'AX'}):
            return None

        # 1. 更新物理实态 x' (物理系统根据原始事件演化)
        next_state_system = transition_origin_system.get((cur_sys_x, event))
        if next_state_system is None:
            return None # 物理上不可能发生的事件
        
        # 监督器当前禁止的事件
        if transition_supervisor.get((cur_sup_z, event)) is None:
            return None 
            
        # 【移除】：原有的 step 2 (更新 xi_A) 已移除，移动到下一步骤

        # 3. 获取篡改选项
        tempered_events = GenerateACAGFunctionTools.tamper_events(
            event_vulnerable,
            event_attacker_alterable,
            event
        )

        # 返回攻击状态 Ya
        # 【升维】：
        # 1. 此时传递的是旧的 cur_est_atk (尚未更新)
        # 2. 新增了 event (原始物理事件)，因为下一步更新 xi_A 需要用到它
        # 结构变更为: (xi_S, xi_A_old, z, x', options, original_event)
        next_attacker_ACAG_state = (cur_est_sup, cur_est_atk, cur_sup_z, next_state_system, tuple(tempered_events), event)
        
        return next_attacker_ACAG_state
    
    # 获取攻击状态-环境状态转换关系
    @staticmethod
    def cal_transition_ACAG_attacker_to_environment(current_attacker_ACAG_state,
                                                    estimation_result_supervisor,
                                                    transition_supervisor,
                                                    event_supervisor_unobservable,
                                                    tampered_event, 
                                                    estimation_result_attacker, 
                                                    event_attacker_unobservable):
        '''
        Ya -> Ye' 转换逻辑
        【修改点】：在此处同时更新 xi_S' 和 xi_A'
        '''
        # 1. 解包 Ya: (xi_S, xi_A_old, z, x_new, options, original_event)
        # 注意：这里多解包出一个 original_event，元组长度为 6
        cur_est_sup, cur_est_atk, cur_sup_z, cur_sys_x, _, original_event = current_attacker_ACAG_state
        
        # 【新增逻辑】 2. 更新攻击者预估 xi_A' (基于攻击者看到的原始事件 original_event)
        # 这一步是从上一个函数移动过来的
        next_est_atk = GenerateACAGFunctionTools.update_unobserver_reach_attacker(
            estimation_result_attacker, cur_est_atk, event_attacker_unobservable, cur_sup_z, original_event
        )

        # 3. 更新监督器预估 xi_S' (基于攻击者发出的 tampered_event)
        res_sup = GenerateACAGFunctionTools.update_unobserver_reach_supervisor(
            estimation_result_supervisor, cur_est_sup, event_supervisor_unobservable, tampered_event
        )
        next_est_sup = res_sup if res_sup is not None else frozenset({'AX'})
        
        # 4. 更新监督器内部状态 z' (基于攻击者发出的 tampered_event)
        if tampered_event == 'empty':
            next_state_supervisor = cur_sup_z # 擦除攻击，监督器未观测到事件，状态保持
        else:
            next_state_supervisor = transition_supervisor.get((cur_sup_z, tampered_event))
            # 如果监督器在当前 z 下不接受该事件，进入检测状态 z_det,并且将预估集 xi_S' 中更改为AX
            if next_state_supervisor is None:
                next_state_supervisor = 'z_det'
                next_est_sup = frozenset({'AX'})
        
        # 5. 返回新的环境状态 Ye': (xi_S', xi_A', z', x_new)
        # 注意：这里使用的是刚刚计算出的 next_est_atk
        return (frozenset(next_est_sup), frozenset(next_est_atk), next_state_supervisor, cur_sys_x)

    #生成ACAG转移关系
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

        # 工具函数：确保初始状态非集合
        def to_s(s): return list(s)[0] if isinstance(s, (set, frozenset, list)) else s
        init_z = to_s(state_initial_supervisor)
        init_x = to_s(state_initial_origin)

        # 1. 初始化预估集
        initial_est_sup = GenerateACAGFunctionTools.cal_unobservable_reach_supervisor(
            state_initial_closed_loop_system,
            transition_closed_loop_system,
            event_supervisor_unobservable
        )
        # 初始攻击者预估需要考虑初始 z0 的约束
        initial_est_atk = GenerateACAGFunctionTools.cal_unobservable_reach_attacker(
            {init_x}, # 传入集合
            transition_origin_system,
            event_attacker_unobservable,
            transition_supervisor,
            init_z
        )
        
        initial_env_state = (initial_est_sup, initial_est_atk, init_z, init_x)
        environment_ACAG_states.add(initial_env_state)
        queue = deque([initial_env_state])

        while queue:
            curr_env_state = queue.popleft()
            
            # 终止检查
            if curr_env_state[0] == frozenset({'AX'}): continue
            if len(curr_env_state[1]) > 0 and curr_env_state[1].issubset(secret_states): continue

            curr_xi_S, curr_xi_A, curr_z, curr_x = curr_env_state

            # --- Ye -> Ya ---
            # 遍历物理系统当前状态下可发生的所有事件 sigma
            for (state_in_origin, sigma), next_x_in_dict in transition_origin_system.items():
                if state_in_origin == curr_x:
                    
                    # 【修改点】：调用 Ye -> Ya 时减少参数
                    next_atk_state = ACAGSystemCreater.cal_transition_ACAG_environment_to_attacker(
                        curr_env_state,
                        sigma,
                        event_vulnerable,
                        event_attacker_alterable,
                        transition_supervisor,
                        transition_origin_system
                    )
                    
                    if next_atk_state:
                        all_ACAG_transition[(curr_env_state, sigma)] = next_atk_state
                        
                        if next_atk_state not in attacker_ACAG_states:
                            attacker_ACAG_states.add(next_atk_state)
                            
                            # --- Ya -> Ye' ---
                            # 注意：next_atk_state 现在长度为 6，options 位于倒数第二位 [-2]
                            options = next_atk_state[-2] 
                            for tampered_sigma in options:
                                # 【修改点】：调用 Ya -> Ye' 时增加参数
                                next_env_state = ACAGSystemCreater.cal_transition_ACAG_attacker_to_environment(
                                    next_atk_state,
                                    estimation_result_supervisor,
                                    transition_supervisor,
                                    event_supervisor_unobservable,
                                    tampered_sigma,
                                    estimation_result_attacker,   # 新增
                                    event_attacker_unobservable   # 新增
                                )

                                if next_env_state:
                                    all_ACAG_transition[(next_atk_state, tampered_sigma)] = next_env_state
                                    
                                    if next_env_state not in environment_ACAG_states:
                                        environment_ACAG_states.add(next_env_state)
                                        queue.append(next_env_state)

        return all_ACAG_transition, initial_env_state

    @staticmethod
    def draw_ACAG_graph(all_ACAG_transition, 
                        initial_env_state, 
                        secret_states,
                        labled_unobservable_reachable_supervisor, 
                        labled_unobservable_reachable_attacker,
                        filename):
        if isinstance(all_ACAG_transition, tuple):
            all_ACAG_transition = all_ACAG_transition[0]

        dot = graphviz.Digraph(comment='ACAG System', format='svg')
        
        # ... (图例生成代码省略，保持不变) ...
        # --- 1. 构建列表式图例字符串 ---
        legend_html = '''<'''
        legend_html += '''<FONT POINT-SIZE="16">'''
        legend_html += '<B>State enstimation of supervisor:</B><BR ALIGN="LEFT"/><BR ALIGN="LEFT"/>'
        for key, Value in labled_unobservable_reachable_supervisor.items():
            if isinstance(Value, (frozenset, set)):
                value_str = '{' + ','.join(map(str, Value)) + '}'
            else:
                value_str = str(Value)
            legend_html += f'{key}:{value_str}<BR ALIGN="LEFT"/><BR ALIGN="LEFT"/>'
        
        legend_html += '<B>State enstimation of attacker:</B><BR ALIGN="LEFT"/><BR ALIGN="LEFT"/>'
        for key, Value in labled_unobservable_reachable_attacker.items():
            if isinstance(Value, (frozenset, set)):
                value_str = '{' + ','.join(map(str, Value)) + '}'
            else:
                value_str = str(Value)
            legend_html += f'{key}:{value_str}<BR ALIGN="LEFT"/><BR ALIGN="LEFT"/>'
        legend_html += '</FONT>'
        legend_html += '        >'

        # --- 2. 全局属性设置 ---
        dot.attr(
            label=legend_html,      
            labelloc='t',           
            labeljust='l',          
            rankdir='TB',
            nodesep='0.25',         
            ranksep='0.3',          
            fontname='serif',       
            fontsize='11',
            splines='spline',         
            overlap='false',
            forcelabels='true'
        )

        sup_val_to_label = {v: k for k, v in labled_unobservable_reachable_supervisor.items()}
        atk_val_to_label = {v: k for k, v in labled_unobservable_reachable_attacker.items()}

        def get_id(state):
            return hex(hash(state) & 0xffffffff)

        adj_map = {}
        possible_nodes = set()
        for (curr, event), next_s in all_ACAG_transition.items():
            if curr not in adj_map: adj_map[curr] = []
            adj_map[curr].append((event, next_s))
            possible_nodes.add(curr)
            possible_nodes.add(next_s)

        real_start_node = next((n for n in possible_nodes if len(n) == 4 and str(n).replace("set", "frozenset") == str(initial_env_state).replace("set", "frozenset")), 
                               next((n for n in possible_nodes if len(n) == 4), None))

        queue = deque([real_start_node]) if real_start_node else deque()
        visited = {real_start_node} if real_start_node else set()
        ye_map = {real_start_node: "ye0"} if real_start_node else {}
        ye_counter = 1

        if real_start_node:
            dot.node('start_node', label='', shape='none', width='0', height='0')
            dot.edge('start_node', get_id(real_start_node), arrowsize='0.6')

        while queue:
            curr_state = queue.popleft()
            curr_id = get_id(curr_state)
            
            # --- Ye 节点 (长度为 4) ---
            if len(curr_state) == 4:
                xi_S, xi_A, z, x = curr_state
                s_tag = sup_val_to_label.get(xi_S, "AX" if xi_S == frozenset({'AX'}) else "?")
                a_tag = atk_val_to_label.get(xi_A, "?")
                
                is_ax = (xi_S == 'AX' or xi_S == frozenset({'AX'}) or z == 'z_det')
                is_success = (len(xi_A) > 0 and xi_A.issubset(secret_states))
                
                fill_c, color_c = '#F8F9FA', '#333333'
                if is_ax:        
                    fill_c, color_c = '#FFF1F2', '#9F1239' 
                elif is_success: 
                    fill_c, color_c = '#F0FDF4', '#166534' 

                node_html = f'<<B>{s_tag}, {a_tag}, {x}, {z}</B>>'                    
                dot.node(curr_id, 
                        label=node_html, 
                        xlabel=ye_map.get(curr_state, ""), 
                        fontname='serif',
                        shape='rectangle',      
                        style='filled, rounded', 
                        fillcolor=fill_c, 
                        color=color_c, 
                        margin='0.05,0.02', 
                        width='0',              
                        height='0', 
                        penwidth='1.0',
                        fontsize='10')
            else:
                # --- Ya 节点 ---
                # 因为 Ya 节点现在升维到了 6 (包含 original_event)，所以走 else 分支
                dot.node(curr_id, 
                         label='', 
                         shape='circle', 
                         width='0.08', 
                         height='0.08', 
                         fixedsize='true', 
                         fillcolor='white', 
                         style='filled', 
                         color='black')

            # --- 边绘制 ---
            if curr_state in adj_map:
                for event, next_s in adj_map[curr_state]:
                    if next_s not in visited:
                        visited.add(next_s)
                        if len(next_s) == 4:
                            ye_map[next_s] = f"ye{ye_counter}"
                            ye_counter += 1
                        queue.append(next_s)
                    
                    # 【修改点】：判断源节点是否为 Ya
                    # 现在的 Ya 节点长度是 6，不是 5 了
                    is_from_ya = (len(curr_state) == 6)
                    
                    e_color = '#2563EB' if is_from_ya else '#000000'
                    e_style = 'dashed' if is_from_ya else 'solid'
                    e_text = str(event) if event != 'empty' else '&epsilon;'
                    
                    dot.edge(curr_id, get_id(next_s), 
                             label=f" {e_text} ", 
                             fontname='serif',
                             fontcolor='black',
                             fontsize='9',
                             style=e_style, 
                             color=e_color, 
                             arrowsize='0.6')

        try:
            dot.render(filename, cleanup=True)
            print(f"Graph generated: {filename}.svg")
        except Exception as e:
            print(f"Rendering error: {e}")

        return dot, ye_map