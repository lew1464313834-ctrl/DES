from generate_ACAG_helper import GenerateACAGFunctionTools
from collections import deque
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
                                                    tampered_event):
        # 1. 解包 Ya (维度固定为 5)
        # 最后一个 _ 接收的是那个包含所有可能事件的 tuple，但在本函数中不需要它
        cur_est_sup, cur_est_atk, cur_sup_s, cur_sys_s, _ = current_attacker_ACAG_state
        
        # 2. 更新估计集
        next_est_sup = GenerateACAGFunctionTools.update_unobserver_reach_supervisor(
            estimation_result_supervisor, cur_est_sup, tampered_event
        )
        next_est_atk = GenerateACAGFunctionTools.update_unobserver_reach_attacker(
            estimation_result_attacker, cur_est_atk, event
        )
        
        # 3. 更新实态 (使用元组作为字典的 Key)
        next_state_system = transition_origin_system.get((cur_sys_s, event), cur_sys_s)
        next_state_supervisor = transition_supervisor.get((cur_sup_s, event), cur_sup_s)
        
        # 4. 返回环境状态 (维度回到 4)
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
                                 estimation_result_attacker
                                 ):
        environment_ACAG_states = set()
        attacker_ACAG_states = set()
        all_ACAG_transition = {} 
        
        # 1. 初始化 Ye_0
        # 预估集 (必须是 frozenset)
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
        
        # 物理实态 (确保不是 set 类型，如果是则取元素)
        init_sup_s = list(state_initial_supervisor)[0] if isinstance(state_initial_supervisor, (set, frozenset)) else state_initial_supervisor
        init_ori_s = list(state_initial_origin)[0] if isinstance(state_initial_origin, (set, frozenset)) else state_initial_origin
        
        initial_env_state = (initial_est_sup, initial_est_atk, init_sup_s, init_ori_s)
        
        environment_ACAG_states.add(initial_env_state)
        queue = deque([initial_env_state])
        
        while queue:
            curr_env_state = queue.popleft()
            
            # 如果监督者已报警，该分支停止
            if curr_env_state[0] == frozenset({'AX'}):
                continue
                
            curr_est_sup, curr_est_atk, curr_sup_s, curr_sys_s = curr_env_state

            # --- 步骤 2: Ye -> Ya (仅添加篡改维度) ---
            # 找到在当前物理状态 (curr_sup_s, curr_sys_s) 下闭环系统允许的所有真实事件
            for (state_in_dict, event), next_closed_state in transition_closed_loop_system.items():
                if state_in_dict == (curr_sup_s, curr_sys_s):
                    
                    # 仅添加篡改维度，不更新估计
                    # next_atk_state = (sup_est, atk_est, sup_s, sys_s, (possible_events,))
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
                            
                            # --- 步骤 3: Ya -> Ye' (执行真正的状态更新) ---
                            events_possible = next_atk_state[-1] # 获取篡改后的事件集
                            
                            for tampered_event in events_possible:
                                # 在这里执行复杂的估计更新和物理状态转移
                                next_env_state = ACAGSystemCreater.cal_transition_ACAG_attacker_to_environment(
                                    next_atk_state,
                                    estimation_result_supervisor,
                                    estimation_result_attacker,
                                    transition_closed_loop_system,
                                    transition_origin_system,
                                    transition_supervisor,
                                    event,          # 物理真实事件
                                    tampered_event  # 攻击者发出的事件
                                )
                                
                                # 记录 Ya --(tampered_event)--> Ye'
                                all_ACAG_transition[(next_atk_state, tampered_event)] = next_env_state
                                
                                if next_env_state not in environment_ACAG_states:
                                    environment_ACAG_states.add(next_env_state)
                                    queue.append(next_env_state)
        
        return all_ACAG_transition