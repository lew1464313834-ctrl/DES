from collections import deque,defaultdict

"""
给定初始所有的系统假设
"""


class SystemAssumptions:
    def __init__(self):
        self.state_oringin_system = {0, 1, 2, 3, 4, 5, 6, 7, 8}
        self.state_supervisor = {0, 1, 2}
        self.state_under_controlled_system = {
            (0, 0),
            (0, 1),
            (0, 2),
            (0, 5),
            (0, 4),
            (1, 0),
            (1, 1),
            (1, 2),
            (1, 3),
            (1, 4),
            (1, 5),
            (1, 6),
            (1, 7),
            (2, 3),
            (2, 6),
        }
        self.state_initial_origin_ststem = {0}
        self.state_initial_under_controlled_ststem = {(0, 0)}
        self.state_initial_supervisor = {0}
        self.state_system_secret = {5}

        self.event = {"o1", "o2", "o3", "o4", "uo1","uo2","uo3","empty"}
        self.event_attacker_observable = {"o2", "o3", "o4"}
        self.event_supervisor_observable = {"o1", "o2", "o3"}
        self.event_supervisor_controllable = {"o3","uo3"}
        self.event_vulnerable = {"o2","o3"}
        self.event_alterable = {"o2","o3", "empty"}

        self.transition_origin_system = {
            # ---------------------------------
            # state 0
            # ---------------------------------
            (0, "o1"): 1,
            (0, "o2"): 3,
            (0, "o3"): 7,
            (0, "o4"): 5,
            (0, "empty"): 0,

            # ---------------------------------
            # state 1
            # ---------------------------------
            (1, "uo2"): 2,
            (1, "empty"): 1,

            # ---------------------------------
            # state 2
            # ---------------------------------
            (2, "o1"): 5,
            (2, "empty"): 2,

            # ---------------------------------
            # state 3
            # ---------------------------------
            (3, "o4"): 6,
            (3, "empty"): 3,

            # ---------------------------------
            # state 4
            # ---------------------------------
            (4, "o2"): 1,
            (4, "o1"): 6,
            (4, "empty"): 4,

            # ---------------------------------
            # state 5
            # ---------------------------------
            (5, "o4"): 0,
            (5, "empty"): 5,

            # ---------------------------------
            # state 6
            # ---------------------------------
            (6, "uo3"): 7,
            (6, "empty"): 6,

            # ---------------------------------
            # state 7
            # ---------------------------------
            (7, "o3"): 8,
            (7,"uo1"):4,
            (7, "empty"): 7,

            # ---------------------------------
            # state 8
            # ---------------------------------
            (8, "o2"):5,
            (8, "o3"): 4,
            (8, "empty"): 8
        }

        self.transition_supervisor = {
            # =========================
            # supervisor state z0
            # =========================
            (0, "o1"): 0,
            (0, "o2"): 2,
            (0, "o3"): 1,
            (0, "o4"): 0,
            (0, "uo1"): 0,
            (0, "uo2"): 0,
            (0, "uo3"): 0,
            (0, "empty"): 0,

            # =========================
            # supervisor state z1
            # =========================
            (1, "o1"): 1,
            (1, "o2"): 1,
            (1, "o3"): 1,
            (1, "o4"): 1,
            (1, "uo1"): 1,
            (1, "uo2"): 1,
            (1, "uo3"): 1,
            (1, "empty"): 1,

            # =========================
            # supervisor state z2
            # =========================
            (2, "o1"): 2,
            (2, "o2"): 2,
            (2, "o3"): 2,
            (2, "o4"): 2,
            (2, "uo1"): 2,
            (2, "uo2"): 2,
            (2, "uo3"): 2,
            (2, "empty"): 2,
        }
       

        self.transition_under_controlled_system = {
            # ========================          
            # z0 layer
            # =========================
            ((0, 0), "o1"): (0, 1),
            ((0, 0), "o2"): (2, 3),
            ((0, 0), "o3"): (1, 7),
            ((0, 0), "empty"): (0, 0),

            ((0, 1), "uo2"): (0, 2),
            ((0, 1), "empty"): (0, 1),

            ((0, 2), "o1"): (0, 5),
            ((0, 2), "empty"): (0, 2),

            ((0, 5), "o4"): (0, 0),
            ((0, 5), "empty"): (0, 5),

            # =========================
            # z1 layer
            # =========================
            ((1, 0), "o2"): (1, 3),
            ((1, 0), "o1"): (1, 1),
            ((1, 0), "empty"): (1, 0),

            ((1, 1), "uo2"): (1, 2),
            ((1, 1), "empty"): (1, 1),

            ((1, 2), "o1"): (1, 5),
            ((1, 2), "empty"): (1, 2),

            ((1, 3), "o4"): (1, 6),
            ((1, 3), "empty"): (1, 3),

            ((1, 4), "o2"): (1, 1),
            ((1, 4), "o1"): (1, 6),
            ((1, 4), "empty"): (1, 4),

            ((1, 5), "o4"): (1, 0),
            ((1, 5), "empty"): (1, 5),

            ((1, 6), "uo3"): (1, 7),
            ((1, 6), "empty"): (1, 6),

            ((1, 7), "uo1"): (1, 4),
            ((1, 7), "empty"): (1, 7),

            # =========================
            # z2 layer
            # =========================
            ((2, 3), "o4"): (2, 6),
            ((2, 3), "empty"): (2, 3),

            ((2, 6), "empty"): (2, 6),
        }


    def generate_language_closed_loop_system(self, max_depth=8):
        """
        生成闭环系统的形式语言 L = { [[前缀][循环]] }
        核心修复：循环必须基于当前状态动态计算，而非预计算的SCC循环
        """
        # 1. 构建非empty转移图（只包含有定义的转移）
        graph = defaultdict(list)
        for (s, e), s_next in self.transition_under_controlled_system.items():
            if e != 'empty':
                graph[s].append((e, s_next))
        
        # 2. 可达状态计算
        reachable = set()
        queue = deque(self.state_initial_under_controlled_ststem)
        reachable.update(queue)
        while queue:
            s = queue.popleft()
            for _, s_next in graph[s]:
                if s_next not in reachable:
                    reachable.add(s_next)
                    queue.append(s_next)
        
        # 3. Tarjan SCC（用于识别循环状态集合）
        index = 0
        stack, indices, lowlink, on_stack = [], {}, {}, set()
        sccs = []
        
        def strongconnect(v):
            nonlocal index
            indices[v] = lowlink[v] = index; index += 1
            stack.append(v); on_stack.add(v)
            for _, w in graph[v]:
                if w not in reachable: continue
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
        
        for v in reachable:
            if v not in indices:
                strongconnect(v)
        
        # 4. 将状态映射到其所属SCC（用于快速查找）
        state_to_scc = {}
        for scc in sccs:
            for state in scc:
                state_to_scc[state] = scc
        
        # 5. BFS枚举语言（动态计算每个状态的循环）
        language = []
        visited = set()
        queue = deque([(s0, ()) for s0 in self.state_initial_under_controlled_ststem])
        
        # 辅助函数：从特定状态s出发找最短循环
        def find_cycle_from_state(s, scc_set):
            """在SCC内从状态s出发找最短返回路径"""
            if not scc_set:
                return []
            
            # 单状态检查自环
            if len(scc_set) == 1:
                for ev, tgt in graph[s]:
                    if tgt == s:
                        return [ev]
                return []
            
            # 多状态BFS
            q = deque([(s, [])])
            visited_bfs = {s}
            
            while q:
                cur, path = q.popleft()
                for ev, nxt in graph[cur]:
                    if nxt not in scc_set: continue
                    if nxt == s and path:  # 返回起点且非空路径
                        return path + [ev]
                    if nxt not in visited_bfs:
                        visited_bfs.add(nxt)
                        q.append((nxt, path + [ev]))
            return []
        
        while queue:
            s, prefix = queue.popleft()
            if len(prefix) > max_depth or (s, prefix) in visited:
                continue
            visited.add((s, prefix))
            
            # 动态计算当前状态的循环（关键修复）
            loop = []
            if s in state_to_scc:
                scc = state_to_scc[s]
                # 检查s是否为循环状态（有返回路径）
                loop = find_cycle_from_state(s, scc)
            
            language.append([prefix, loop])
            
            # 扩展转移
            for ev, s_next in graph[s]:
                new_prefix = prefix + (ev,)
                if len(new_prefix) <= max_depth and (s_next, new_prefix) not in visited:
                    queue.append((s_next, new_prefix))
        
        # 6. 去重和排序
        unique_lang = {tuple(pref): [pref, loop] for pref, loop in language}
        sorted_lang = sorted(unique_lang.values(), key=lambda x: (len(x[0]), x[0]))
        
        if not sorted_lang or sorted_lang[0][0] != ():
            sorted_lang.insert(0, [(), []])
        
        # 7. 验证并打印统计
        print(f"✅ 生成语言: {len(sorted_lang)} 条前缀")        
        return sorted_lang


# 测试
assumption = SystemAssumptions()
language = assumption.generate_language_closed_loop_system()
print("语言前缀与循环段：",language)
