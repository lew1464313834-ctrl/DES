from collections import deque, defaultdict
from graphviz import Digraph

class HelperFunctionColledtion:
    #计算攻击者单次不可观测可达集
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


    # 生成监督器视角的转移关系
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
        initial_estimation_supervisor = HelperFunctionColledtion.cal_unobservable_reach([initial_physical_state], transition_closed_loop_system, event_ubobservable_supervisor)

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
                    next_estimate = HelperFunctionColledtion.cal_unobservable_reach(next_physical_states, transition_closed_loop_system, event_ubobservable_supervisor)
                    
                    # 记录转移关系
                    estimation_result_set_supervisor[(curr_estimate, event)] = next_estimate
                    
                    if next_estimate not in visited_estimates:
                        visited_estimates.add(next_estimate)
                        queue.append(next_estimate)
        
        return estimation_result_set_supervisor

    # 生成攻击者视角的转移关系

    def generate_unobserver_reach_attacker(state_initial_origin,
                                        transition_closed_loop_system, 
                                        transition_origin_system,
                                        event_attacker_observable, 
                                        events_unobservale_attacker
                                        ):
        """
        生成攻击者视角的转移关系。
        
        逻辑：
        - 遍历分支：基于 transition_closed_loop_system (实际发生了什么)
        - 状态更新：基于 transition_origin_system (物理上认为可能到哪)
        """

        # 1. 初始不可观测闭包计算 (基于原始系统)
        # 假设攻击者认为初始状态是物理态 0，他会根据物理模型计算不可观测闭包
        initial_x_estimation = HelperFunctionColledtion.cal_unobservable_reach(
            state_initial_origin, 
            transition_origin_system, 
            events_unobservale_attacker
        )
        # 转为元组作为 Key
        initial_x_tuple = tuple(sorted(initial_x_estimation))

        # 2. BFS 初始化
        # 我们需要同时跟踪：当前的物理预估集(x_set) 和 背后支撑它的闭环状态集(closed_set)
        # 因为只有闭环状态集能告诉我们“受控系统接下来真正能走什么”
        estimation_result_attacker = {}
        
        # 初始闭环种子 (z0, x0)
        initial_closed_seeds = set((0, x) for x in state_initial_origin)
        initial_closed_set = HelperFunctionColledtion.cal_unobservable_reach(
            initial_closed_seeds, 
            transition_closed_loop_system, 
            events_unobservale_attacker
        )

        # queue 存储: (当前物理预估集元组, 当前闭环状态集)
        queue = deque([(initial_x_tuple, initial_closed_set)])
        visited_states = {(initial_x_tuple, initial_closed_set)}

        while queue:
            curr_x_view, curr_closed_set = queue.popleft()
            
            # 遍历攻击者可观测事件
            for sigma in event_attacker_observable:
                # --- A. 确定受控系统在 sigma 下能到达的所有“种子” ---
                next_closed_seeds = set()
                for closed_state in curr_closed_set:
                    if (closed_state, sigma) in transition_closed_loop_system:
                        next_closed_seeds.add(transition_closed_loop_system[(closed_state, sigma)])
                
                # --- B. 如果受控系统能走 sigma ---
                if next_closed_seeds:
                    # 1. 计算受控系统到达后的新闭环集合 (用于下一轮迭代的“发动机”)
                    next_closed_set = HelperFunctionColledtion.cal_unobservable_reach(
                        next_closed_seeds, 
                        transition_closed_loop_system, 
                        events_unobservale_attacker
                    )

                    # 2. 攻击者更新自己的预估集 (基于物理模型 transition_origin_system)
                    # 攻击者看到 sigma，于是对当前预估集 curr_x_view 中的每个状态尝试 sigma 转移
                    next_x_seeds = set()
                    for x in curr_x_view:
                        if (x, sigma) in transition_origin_system:
                            next_x_seeds.add(transition_origin_system[(x, sigma)])
                    
                    # 计算物理模型下的不可观测闭包
                    next_x_estimation = HelperFunctionColledtion.cal_unobservable_reach(
                        next_x_seeds, 
                        transition_origin_system, 
                        events_unobservale_attacker
                    )
                    next_x_view = tuple(sorted(next_x_estimation))

                    # 3. 记录结果
                    estimation_result_attacker[(curr_x_view, sigma)] = next_x_view
                    
                    # 4. 判重并入队
                    state_pair = (next_x_view, next_closed_set)
                    if state_pair not in visited_states:
                        visited_states.add(state_pair)
                        queue.append(state_pair)
        
        return estimation_result_attacker
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
            return event_alterable
        else:
            return event
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
