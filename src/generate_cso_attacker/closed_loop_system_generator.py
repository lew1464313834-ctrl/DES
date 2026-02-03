from typing import Set, Dict, Any, List, Tuple
from collections import deque
from graphviz import Digraph

"""
给定初始所有的系统假设
"""
# 系统假设
class SystemAssumptions:
    def __init__(
        self,
        state_oringin_system:Set[int],
        state_supervisor:Set[int],
        state_initial_origin_ststem:Set[int],
        state_initial_supervisor:Set[int],
        state_system_secret:Set[int],
        event_system :Set[str],
        event_attacker_observable:Set[str],
        event_supervisor_observable:Set[str],
        event_supervisor_controllable:Set[str],
        event_vulnerable:Set[str],
        event_alterable:Set[str],
        transition_origin_system:Dict[Any,Any],
        transition_supervisor:Dict[Any,Any],
        ):
        self.state_oringin_system = state_oringin_system
        self.state_supervisor = state_supervisor
        self.state_initial_origin_ststem = state_initial_origin_ststem
        self.state_initial_supervisor = state_initial_supervisor
        self.state_system_secret = state_system_secret
        self.event_system = event_system
        self.event_attacker_observable = event_attacker_observable
        self.event_supervisor_observable = event_supervisor_observable
        self.event_supervisor_controllable = event_supervisor_controllable
        self.event_vulnerable = event_vulnerable
        self.event_alterable = event_alterable
        self.transition_origin_system = transition_origin_system
        self.transition_supervisor = transition_supervisor

# 闭环系统
class ClosedLoopSystem:
    
    #生成不可观事件集
    @staticmethod
    def generate_unobservable_events(system_events,
                                     events_observable):
        unobservable_events = system_events - events_observable
        event_ubobservable_supervisor = {e for e in unobservable_events if e != 'empty'}
        return event_ubobservable_supervisor
    
    @staticmethod
    # 生成闭环系统的状态集合
    def generate_states_closed_loop_system(
        state_initial_origin_ststem, 
        state_initial_supervisor,
        event_system,
        transition_origin_system,
        transition_supervisor,
        max_depth=15 # 增加默认深度以覆盖更完整的状态空间
        ):
        """
        通过可达性搜索生成闭环系统的所有状态集合。
        :return: 闭环系统状态集合，元素格式为 (supervisor_state, origin_system_state)
        """
        states_closed_loop_system = list()
        
        # 1. 确定初始状态对并加入队列
        # 初始状态对集合由监督器初始状态和系统初始状态的笛卡尔积构成
        queue = deque()
        for s_init in state_initial_supervisor:
            for o_init in state_initial_origin_ststem:
                initial_pair = (s_init, o_init)
                if initial_pair not in states_closed_loop_system:
                    states_closed_loop_system.append(initial_pair)
                    queue.append((initial_pair, 0)) # 存储 (状态对, 当前深度)

        # 2. 广度优先搜索 (BFS) 遍历可达状态
        while queue:
            (curr_s, curr_o), depth = queue.popleft()
            
            # 超过最大深度限制则停止扩展该分支
            if depth >= max_depth:
                continue
                
            # 遍历系统中可能发生的所有事件
            for event in event_system:
                o_key = (curr_o, event)
                s_key = (curr_s, event)
                
                # 只有当原系统和监督器在当前状态下都定义了该事件时，转移才有效
                if o_key in transition_origin_system and s_key in transition_supervisor:
                    next_o = transition_origin_system[o_key]
                    next_s = transition_supervisor[s_key]
                    next_pair = (next_s, next_o)
                    
                    # 如果是新发现的状态，记录并加入搜索队列
                    if next_pair not in states_closed_loop_system:
                        states_closed_loop_system.append(next_pair)
                        queue.append((next_pair, depth + 1))
                states_closed_loop_system.sort()   
        return states_closed_loop_system
    
    #闭环系统初始状态
    @staticmethod
    def generate_states_initial_closed_loop_system(
        state_initial_supervisor,
        state_initial_origin_ststem,
        states_closed_loop_system
        ):
        """
        生成初始状态集合。
        """
        initial_states = []
        for s_init in state_initial_supervisor:
            for o_init in state_initial_origin_ststem:
                if (s_init, o_init) in states_closed_loop_system:
                    initial_states.append((s_init, o_init))
        return initial_states
   #生成闭环系统转换关系
    @staticmethod
    def generate_transition_closed_loop_system(
        state_oringin_system,
        state_initial_origin_ststem,
        state_initial_supervisor,
        event_system,
        transition_origin_system,
        transition_supervisor,
        max_depth=8
        ):
        """
        生成闭环系统的状态转移图。
        采用可达性搜索算法（BFS）构建受控系统的状态转移。
        """
        closed_loop_transitions = {}
        
        # 初始状态对集合（通常为单元素，但根据输入定义为 Set）
        # 我们需要处理所有可能的初始状态组合
        initial_states = []
        for s_init in state_initial_supervisor:
            for o_init in state_initial_origin_ststem:
                initial_states.append((s_init, o_init))
        
        # 使用队列进行可达性搜索
        queue = initial_states.copy()
        visited_states = set(initial_states)
        
        while queue:
            curr_s_state, curr_o_state = queue.pop(0)
            
            # 遍历系统中可能发生的所有事件
            for event in event_system:
                # 定义查找键
                o_key = (curr_o_state, event)
                s_key = (curr_s_state, event)
                
                # 只有当原系统和监控器都定义了该事件的转移时，闭环系统才发生转移
                # 在监督控制理论中，监控器通过不定义某些可控事件来达到“禁止”的效果
                if o_key in transition_origin_system and s_key in transition_supervisor:
                    next_o_state = transition_origin_system[o_key]
                    next_s_state = transition_supervisor[s_key]
                    
                    next_combined_state = (next_s_state, next_o_state)
                    
                    # 记录闭环转移关系：((s_curr, o_curr), event) -> (s_next, o_next)
                    closed_loop_transitions[((curr_s_state, curr_o_state), event)] = next_combined_state
                    
                    # 如果到达了新状态，加入队列继续搜索
                    if next_combined_state not in visited_states:
                        visited_states.add(next_combined_state)
                        queue.append(next_combined_state)
                        
        return closed_loop_transitions
    

    # 生成闭环系统图
    @staticmethod
    def generate_closed_loop_system_graph(transition_closed_loop_system, 
                                        initial_states,
                                        event_system,
                                        event_attacker_observable,
                                        event_vulnerable,
                                        event_supervisor_observable,
                                        event_supervisor_controllable,
                                        state_system_secret,
                                        file_name): # 增加秘密状态参数
        
        dot = Digraph(comment='Closed Loop System', format='svg')
        dot.attr(rankdir='LR', size='10')
        dot.attr('node', shape='circle', fixedsize='true', width='0.6')

        # 1. 预处理转移关系，提高搜索效率 (邻接表)
        adj = {}
        for (src, event), target in transition_closed_loop_system.items():
            if src not in adj:
                adj[src] = []
            adj[src].append((event, target))

        # 2. 优化后的颜色逻辑 (根据图片示例调整优先级)
        def get_event_color(event):
            if event in event_vulnerable: return "red"
            if event in event_attacker_observable: return "blue"
            if event in event_supervisor_controllable: return "cyan"
            if event in event_supervisor_observable: return "green"
            if event == "empty": return "gray"
            return "black"

        visited = set()
        queue = []

        # 3. 处理初始状态并添加标识箭头
        if initial_states:
            for i, s_init in enumerate(initial_states):
                # 添加虚拟节点指向初始状态
                init_name = f"start_{i}"
                dot.node(init_name, label="", shape="none", width="0")
                dot.edge(init_name, str(s_init))
                queue.append((s_init, 0))

        max_depth = 15 # 适当增加深度以显示完整系统

        while queue:
            curr_state, depth = queue.pop(0)
            if curr_state in visited or depth > max_depth:
                continue
            visited.add(curr_state)

            # 4. 节点属性：如果是秘密状态，设置背景色
            node_id = str(curr_state)
            label = f"{curr_state[0]},{curr_state[1]}"
            
            if state_system_secret and curr_state[1] in state_system_secret:
                dot.node(node_id, label=label, style="filled", fillcolor="pink")
            else:
                dot.node(node_id, label=label)

            # 5. 只遍历当前节点的邻居
            for event, target in adj.get(curr_state, []):
                color = get_event_color(event)
                dot.edge(node_id, str(target), label=event, color=color, fontcolor=color)
                
                if target not in visited:
                    queue.append((target, depth + 1))
        dot.render(file_name, view=False, cleanup=True)
        
        return dot
    
    # 生成闭环系统的语言
    @staticmethod
    def generate_language_closed_loop_system(transition_closed_loop_system, 
                                         state_initial_closed_loop_system,
                                         max_depth=8):
        """
        根据闭环转移字典生成语言。
        transition_closed_loop_system 格式: {((s, o), 'event'): (ns, no), ...}
        """

        # 1. 结果集初始化（包含空迹）
        language = {()}
        
        # 2. 预处理转移字典，构建邻接表以提高搜索效率
        # 结构: { curr_state: [(event, next_state), ...] }
        adj_map = {}
        for key, next_state in transition_closed_loop_system.items():
            # 你的键结构是 ((s, o), event)
            if isinstance(key, tuple) and len(key) == 2:
                curr_state, event = key
                if curr_state not in adj_map:
                    adj_map[curr_state] = []
                adj_map[curr_state].append((event, next_state))

        # 3. 规范化初始状态：确保它是可迭代的列表或集合
        if isinstance(state_initial_closed_loop_system, tuple):
            # 如果用户传的是 (0,0) 而不是 [(0,0)]
            if isinstance(state_initial_closed_loop_system[0], int):
                queue = [(state_initial_closed_loop_system, (), 0)]
            else:
                queue = [(s, (), 0) for s in state_initial_closed_loop_system]
        else:
            queue = [(s, (), 0) for s in state_initial_closed_loop_system]

        # 4. BFS 搜索路径
        while queue:
            curr_state, curr_path, depth = queue.pop(0)
            
            if depth >= max_depth:
                continue
                
            if curr_state in adj_map:
                for event, next_state in adj_map[curr_state]:
                    # 过滤 'empty' 事件。如果 'empty' 代表自环，它不属于语言中的有效事件
                    if event == 'empty':
                        # 如果需要继续探索自环后的路径（但在你的数据中自环不改变状态），
                        # 此处跳过即可，否则 depth 会被无效自环耗尽
                        continue
                    
                    # 生成新路径
                    new_path = curr_path + (event,)
                    
                    # 记录路径
                    language.add(new_path)
                    
                    # 状态空间搜索去重：(状态, 路径)
                    # 只有新路径才继续搜索
                    queue.append((next_state, new_path, depth + 1))
                    
        return language