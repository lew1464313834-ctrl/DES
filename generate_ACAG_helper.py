from collections import deque

class GenerateACAGFunctionTools:
    #计算单次不可观测可达集
    @staticmethod
    def cal_unobservable_reach(states_current_estimation, 
                                          transition, 
                                          events_unobeservable, 
                                          max_depth=15):
        state_next_estiamtion_supervisor = set(states_current_estimation)
        queue = deque([(s, 0) for s in states_current_estimation])
        
        while queue:
            curr_state, depth = queue.popleft()
            if depth >= max_depth: 
                continue
            # 搜索所有以当前预估为起点的不可观测转移
            for (src, event), target in transition.items():
                if src == curr_state and event in events_unobeservable:
                    if target not in state_next_estiamtion_supervisor:
                        state_next_estiamtion_supervisor.add(target)
                        queue.append((target, depth + 1))
        return frozenset(state_next_estiamtion_supervisor)


    # 生成监督器视角的所有转移关系
    @staticmethod
    def generate_unobserver_reach_supervisor(states_closed_loop_system, 
                                      transition_closed_loop_system,
                                        observable_events, 
                                      event_ubobservable_supervisor):
        """
        生成观察者视角的转移关系。
        输出格式: {(当前估算集合, 观测事件): 结果估算集合}
        """

        # 1. 找到初始估算集 xi_0
        # 假设 (0,0) 是唯一的物理初始态
        initial_physical_state = (0, 0) 
        initial_estimation_supervisor = GenerateACAGFunctionTools.cal_unobservable_reach([initial_physical_state], transition_closed_loop_system, event_ubobservable_supervisor)

        # 2. BFS 搜索所有可达的估算集合
        estimation_result_set_supervisor = {}
        visited_estimates = {initial_estimation_supervisor}
        queue = deque([initial_estimation_supervisor])

        while queue:
            curr_estimate = queue.popleft()
            
            # 遍历每一个可能的观测事件
            for event in observable_events:
                # 找到从当前集合出发，通过 event 能到达的物理状态
                next_physical_states = set()
                for state in curr_estimate:
                    if (state, event) in transition_closed_loop_system:
                        next_physical_states.add(transition_closed_loop_system[(state, event)])
                
                # 如果有转移发生
                if next_physical_states:
                    # 计算到达状态的不可观测可达集
                    next_estimate = GenerateACAGFunctionTools.cal_unobservable_reach(next_physical_states, transition_closed_loop_system, event_ubobservable_supervisor)
                    
                    # 记录转移关系
                    estimation_result_set_supervisor[(curr_estimate, event)] = next_estimate
                    
                    if next_estimate not in visited_estimates:
                        visited_estimates.add(next_estimate)
                        queue.append(next_estimate)
        
        return estimation_result_set_supervisor
    
    #更新单次监督器预估
    @staticmethod
    def update_unobserver_reach_supervisor(estimation_result_set_supervisor,
                                           current_estimation_supervisor,
                                           event):
        """
        带攻击检测的监督器预估更新。
        - 如果当前预估已经是报警状态，保持报警。
        - 如果验证失败，触发 AX。
        - 如果验证通过，返回预计算的结果。
        """
        # 1. 状态保持：如果已经是报警态，则不再恢复，如果是空事件，则返回原估计
        if current_estimation_supervisor == frozenset({'AX'}):
            return frozenset({'AX'})
        if event == 'empty':
            return current_estimation_supervisor

        # 2. 查表逻辑：获取预计算好的不可观测闭包
        # 使用 .get() 防止因攻击者构造了预计算中不存在的异常路径而导致程序崩溃
        lookup_key = (current_estimation_supervisor, event)
        next_estimate = estimation_result_set_supervisor.get(lookup_key)
        
        if next_estimate is None:
            # 如果发生了预计算之外的观测，认为是异常
            return frozenset({'AX'})
            
        return next_estimate

    # 生成攻击者视角的所有转移关系
    @staticmethod
    def generate_unobserver_reach_attacker(state_initial_origin, 
                                           transition_origin_system,
                                           event_attacker_observable, 
                                           uo_events_attacker):
        initial_x_view = GenerateACAGFunctionTools.cal_unobservable_reach(
            state_initial_origin, 
            transition_origin_system, 
            uo_events_attacker
        )

        estimation_result_attacker = {}
        queue = deque([initial_x_view])
        visited = {initial_x_view}

        while queue:
            curr_x_view = queue.popleft()
            for sigma in event_attacker_observable:
                next_x_seeds = set()
                for x in curr_x_view:
                    if (x, sigma) in transition_origin_system:
                        next_x_seeds.add(transition_origin_system[(x, sigma)])
                
                if next_x_seeds:
                    next_x_view = GenerateACAGFunctionTools.cal_unobservable_reach(
                        next_x_seeds, 
                        transition_origin_system, 
                        uo_events_attacker
                    )
                    # 记录时直接使用 frozenset
                    estimation_result_attacker[(curr_x_view, sigma)] = next_x_view
                    
                    if next_x_view not in visited:
                        visited.add(next_x_view)
                        queue.append(next_x_view)
        
        return estimation_result_attacker
    
    #更新单次攻击者预估
    @staticmethod
    def update_unobserver_reach_attacker(estimation_result_attacker,
                                         current_estimation_attacker,
                                         event):
        if event == 'empty':
            return current_estimation_attacker
        lookup_key = (current_estimation_attacker, event)
        next_estimate = estimation_result_attacker.get(lookup_key)
        return next_estimate

    # 验证结果
    def verify_unobservable_reach_results(result):
        for i, ((curr_set, event), next_set) in enumerate(result.items(), 1):
            # 将 frozenset 转为 sorted list 方便阅读
            curr_list = sorted(list(curr_set))
            next_list = sorted(list(next_set))
            print(f"{i}: {{ {tuple(curr_list) if len(curr_list)>1 else curr_list[0]}, {event} }} : frozenset({next_list})")
    
    # 单次篡改函数
    @staticmethod
    def tamper_events(event_vulnerable, event_alterable, event):
        if event in event_vulnerable:
            return tuple(event_alterable)
        else:
            return (event,)
    #监督器验证单次事件
    @staticmethod
    def verify_supervisor_single_event(transuition_closed_loop_system,
                                       transition_supervisor, 
                                       state_current_estimation, 
                                       event):
        next_estimation=set()   
        for state in state_current_estimation:
            if (state, event) in transuition_closed_loop_system:
                return next_estimation
        return {'AX'}
