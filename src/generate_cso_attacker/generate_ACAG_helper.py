from collections import deque

class GenerateACAGFunctionTools:
    #计算监督器单次不可观测可达集
    @staticmethod
    def cal_unobservable_reach_supervisor(states_current_estimation, 
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
    def generate_unobserver_reach_supervisor(
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
        initial_estimation_supervisor = GenerateACAGFunctionTools.cal_unobservable_reach_supervisor([initial_physical_state], transition_closed_loop_system, event_ubobservable_supervisor)

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
                    next_estimate = GenerateACAGFunctionTools.cal_unobservable_reach_supervisor(next_physical_states, transition_closed_loop_system, event_ubobservable_supervisor)
                    
                    # 记录转移关系
                    estimation_result_set_supervisor[(curr_estimate, event)] = next_estimate
                    
                    if next_estimate not in visited_estimates:
                        visited_estimates.add(next_estimate)
                        queue.append(next_estimate)
        
        return estimation_result_set_supervisor
    @staticmethod
    def label_unobserver_reach_supervisor(estimation_result_supervisor):
        '''
        标签化攻击者预估，将一个集合的预估结果用一个符号表示，方便后续绘图
        返回格式: { 'A0': frozenset({...}), 'A1': frozenset({...}), ... }
        '''
        # 1. 提取所有出现的唯一预估集合
        # 预估结果字典的 key 是 (current_est, event), value 是 next_est
        all_unique_sets = set()
        for (curr_set, event), next_set in estimation_result_supervisor.items():
            all_unique_sets.add(curr_set)
            all_unique_sets.add(next_set)
            
        # 2. 对集合进行排序（可选，但排序能保证每次运行生成的 A0, A1 编号顺序一致）
        # 按照集合内元素的字符串表示进行排序
        sorted_sets = sorted(list(all_unique_sets), key=lambda x: str(sorted(list(x))))
        
        # 3. 生成标签映射字典
        labeled_map = {}
        for i, est_set in enumerate(sorted_sets):
            label = f'S{i}'
            labeled_map[label] = est_set
            
        return labeled_map
    #更新单次监督器预估
    @staticmethod
    def update_unobserver_reach_supervisor(estimation_result_set_supervisor,
                                           current_estimation_supervisor,
                                           event_supervisor_unobservable,
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
        if event == 'empty' or event in event_supervisor_unobservable:
            return current_estimation_supervisor

        # 2. 查表逻辑：获取预计算好的不可观测闭包
        lookup_key = (current_estimation_supervisor, event)
        next_estimate = estimation_result_set_supervisor.get(lookup_key)
        
        if next_estimate is None:
            # 如果发生了预计算之外的观测，认为是异常
            return frozenset({'AX'})
            
        return next_estimate


    @staticmethod
    def cal_unobservable_reach_attacker(states_current_estimation, 
                                        transition, 
                                        events_unobeservable,
                                        transition_supervisor, 
                                        current_state_supervisor,
                                        max_depth=15):
        """
        计算攻击者不可观测可达集
        """
        if isinstance(current_state_supervisor, (set, frozenset)):
            if len(current_state_supervisor) == 1:
                z_key = list(current_state_supervisor)[0]
            else:
                z_key = frozenset(current_state_supervisor)
        else:
            z_key = current_state_supervisor

        state_next_estiamtion_attacker = set(states_current_estimation)
        queue = deque([(s, 0) for s in states_current_estimation])
        
        while queue:
            curr_x, depth = queue.popleft()
            
            if depth >= max_depth: 
                continue
                
            for (src_x, event), target_x in transition.items():
                if src_x == curr_x and event in events_unobeservable:
                    
                    if (z_key, event) in transition_supervisor:
                        if target_x not in state_next_estiamtion_attacker:
                            state_next_estiamtion_attacker.add(target_x)
                            queue.append((target_x, depth + 1))
                            
        return frozenset(state_next_estiamtion_attacker)
    @staticmethod
    def generate_unobserver_reach_attacker(state_initial_origin, 
                                           transition_origin_system,
                                           event_attacker_observable,
                                           states_supervisor,
                                           transition_supervisor, 
                                           uo_events_attacker):
        """
        攻击者视角转移生成：物理全集 + 监督器约束演化
        1. 阶段 1 确定物理上攻击者可能产生的预估上限。
        2. 阶段 2 针对每个 z，不仅投影物理集，还演化由于拦截导致的新子集。
        """
        # --- 阶段 1: 计算物理系统的全观察器 (上限) ---
        init_seeds = state_initial_origin if isinstance(state_initial_origin, (set, frozenset)) else {state_initial_origin}
        
        # 初始物理闭包（无监督）
        pure_initial_view = GenerateACAGFunctionTools.cal_unobservable_reach_supervisor(
            init_seeds, transition_origin_system, uo_events_attacker
        )

        physical_observer_states = {pure_initial_view}
        observer_queue = deque([pure_initial_view])
        while observer_queue:
            curr_xi = observer_queue.popleft()
            for sigma in event_attacker_observable:
                next_seeds = {transition_origin_system[(x, sigma)] for x in curr_xi if (x, sigma) in transition_origin_system}
                if next_seeds:
                    next_xi = GenerateACAGFunctionTools.cal_unobservable_reach_supervisor(
                        next_seeds, transition_origin_system, uo_events_attacker
                    )
                    if next_xi not in physical_observer_states:
                        physical_observer_states.add(next_xi)
                        observer_queue.append(next_xi)

        # --- 阶段 2: 结合阶段 1 结果，在 z 约束下进行增量演化 ---
        estimation_result_attacker = {z: {} for z in states_supervisor}

        for z in states_supervisor:
            # 记录在当前 z 下已经处理过的预估集，包含物理全集和演化出的新子集
            visited_in_z = set()
            # 初始探索队列：包含物理全集中的所有预估集（作为潜在的攻击起点）
            # 以及在当前 z 约束下真正能达到的初始预估集
            initial_constrained_xi = GenerateACAGFunctionTools.cal_unobservable_reach_attacker(
                init_seeds, transition_origin_system, uo_events_attacker, transition_supervisor, z
            )
            
            # 将物理全集和初始受限集都放入队列进行演化
            # 这样即使攻击者通过篡改让系统跳到物理集 xi_A，我们也能知道在 z 约束下它后续怎么走
            queue = deque(list(physical_observer_states) + [initial_constrained_xi])
            visited_in_z.update(queue)

            while queue:
                curr_xi = queue.popleft()
                
                for sigma in event_attacker_observable:
                    # 只有当监督器允许 sigma 发生时（系统真实演化路径）
                    if (z, sigma) in transition_supervisor:
                        next_seeds = {transition_origin_system[(x, sigma)] for x in curr_xi if (x, sigma) in transition_origin_system}
                        
                        if next_seeds:
                            # 在 z 约束下计算闭包，产生可能的新结果集（如由于拦截产生的子集）
                            next_xi_constrained = GenerateACAGFunctionTools.cal_unobservable_reach_attacker(
                                next_seeds, 
                                transition_origin_system, 
                                uo_events_attacker, 
                                transition_supervisor, 
                                z
                            )
                            
                            # 存储转移关系
                            estimation_result_attacker[z][(curr_xi, sigma)] = next_xi_constrained
                            
                            # 如果产生了不在 visited_in_z 中的新预估集（例如新的子集演化结果），继续探索
                            if next_xi_constrained not in visited_in_z:
                                visited_in_z.add(next_xi_constrained)
                                queue.append(next_xi_constrained)
                                
        return estimation_result_attacker
    
    @staticmethod
    def label_unobserver_reach_attacker(estimation_result_attacker, states_supervisor):
        """
        标签化攻击者预估。
        """
        all_unique_sets = set()

        # 1. 遍历第一层键（监督器状态 z）
        for z in states_supervisor:
            # 获取该 z 状态下的子字典
            z_dict = estimation_result_attacker.get(z, {})
            
            # 2. 提取子字典中所有的物理预估集（包括 Key 中的起点和 Value 中的终点）
            for (curr_set, event), next_set in z_dict.items():
                all_unique_sets.add(curr_set)
                all_unique_sets.add(next_set)
            
        # 3. 对所有唯一的集合进行排序，保证标签编号的确定性
        # 排序规则：先按集合长度排，再按元素内容的字符串排
        sorted_sets = sorted(list(all_unique_sets), key=lambda x: (len(x), str(sorted(list(x)))))
        
        # 4. 生成标签映射字典 { 'Ai': frozenset }
        labeled_map = {}
        for i, est_set in enumerate(sorted_sets):
            label = f'A{i}'
            labeled_map[label] = est_set
            
        return labeled_map
    
    #更新单次攻击者预估
    @staticmethod
    def update_unobserver_reach_attacker(estimation_result_attacker,
                                         current_estimation_attacker,
                                         event_attacker_unobservable,
                                         current_state_supervisor,
                                         event):
        """
        更新攻击者预估
        """
        # 1. 如果是不可见事件，根据观察者理论，攻击者的预估集不更新
        if event in event_attacker_unobservable:
            return current_estimation_attacker
        
        # 2. 获取当前监督器状态 z 对应的子字典
        # 使用 get 防止 current_state_supervisor 不在字典中导致报错
        z_dict = estimation_result_attacker.get(current_state_supervisor, {})
        
        # 3. 在子字典中查找转移
        lookup_key = (current_estimation_attacker, event)
        next_estimate = z_dict.get(lookup_key)
        
        # 4. 如果没找到（说明在该 z 约束下此转移不可发生），返回空集或 None
        if next_estimate is None:
            return frozenset()
            
        return next_estimate
    
    # 单次篡改函数
    @staticmethod
    def tamper_events(event_vulnerable, event_alterable, event):
        if event in event_vulnerable:
            return tuple(event_alterable)
        else:
            return (event,)
