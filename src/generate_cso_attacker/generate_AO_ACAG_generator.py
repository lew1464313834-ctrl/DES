from collections import deque
import graphviz
class AOACAGSystemCreater:
    @staticmethod
    def generate_AO_ACAG_transition(all_ACAG_transition, initial_env_state, lable_ACAG_map, event_attacker_unobservable):
        """
        生成 AO-ACAG 转移：包含不可观闭包聚类
        """
        
        # 辅助工具：将 ACAG 状态元组转化为标签字符串 (如 'ye0')
        def get_tag(s):
            return lable_ACAG_map.get(s, str(s))

        # 辅助工具：计算 ACAG 环境节点的攻击者不可观闭包
        def get_unobservable_closure(start_states):
            closure = set(start_states)
            stack = list(start_states)
            while stack:
                curr = stack.pop()
                # 遍历从当前 Ye 经过不可观事件到达的下一个 Ye
                # 注意：在您的 ACAG 中，Ye -> Ya -> Ye'。
                # 如果 Ye --(unobs_sigma)--> Ya --(tampered_sigma)--> Ye' 且两者都不可观，则属于闭包
                for (state, sigma), nxt in all_ACAG_transition.items():
                    if state == curr and sigma in event_attacker_unobservable:
                        # 如果 nxt 是 Ya，继续找它发出的不可观决策
                        if len(nxt) == 5: # Ya 节点
                            for (ya_s, t_sigma), ye_next in all_ACAG_transition.items():
                                if ya_s == nxt and t_sigma in event_attacker_unobservable:
                                    if ye_next not in closure:
                                        closure.add(ye_next)
                                        stack.append(ye_next)
            return frozenset(closure)

        def to_tag_tuple(state_set):
            if state_set == 'AX': return 'AX'
            return tuple(sorted([get_tag(s) for s in state_set]))

        # 1. 初始化初始节点的闭包
        q0_set = get_unobservable_closure([initial_env_state])
        q0_tags = to_tag_tuple(q0_set)
        
        ao_transitions = {}
        queue = deque([(q0_set, q0_tags)])
        visited_qe_tags = {q0_tags}

        # 预处理转换关系
        ye_adj = {}
        ya_adj = {}
        for (curr, event), nxt in all_ACAG_transition.items():
            if len(curr) == 4: 
                ye_adj.setdefault(curr, []).append((event, nxt))
            else: 
                ya_adj.setdefault(curr, []).append((event, nxt))

        while queue:
            curr_qe_set, curr_qe_tags = queue.popleft()

            # --- 步骤 A: 聚类 Qe --(可观 sigma)--> Qa ---
            obs_groups = {}
            for ye in curr_qe_set:
                if ye in ye_adj:
                    for sigma, ya in ye_adj[ye]:
                        if sigma not in event_attacker_unobservable: # 仅处理可观事件
                            obs_groups.setdefault(sigma, set()).add(ya)
            
            for sigma, ya_set in obs_groups.items():
                curr_qa_key = (curr_qe_tags, sigma)
                
                # --- 步骤 B: 聚类 Qa --(tampered)--> Qe' ---
                decision_groups = {}
                for ya in ya_set:
                    if ya in ya_adj:
                        for t_sigma, ye_next in ya_adj[ya]:
                            decision_groups.setdefault(t_sigma, set()).add(ye_next)
                
                for t_sigma, next_ye_set in decision_groups.items():
                    # 计算新到达状态的不可观闭包
                    closure_set = get_unobservable_closure(next_ye_set)
                    
                    # 暴露检查
                    is_exposed = any((s[0] == 'AX' or s[0] == frozenset({'AX'})) for s in closure_set)
                    
                    if is_exposed:
                        ao_transitions[(curr_qa_key, t_sigma)] = 'AX'
                    else:
                        next_qe_tags = to_tag_tuple(closure_set)
                        ao_transitions[(curr_qa_key, t_sigma)] = next_qe_tags
                        
                        if next_qe_tags not in visited_qe_tags:
                            visited_qe_tags.add(next_qe_tags)
                            queue.append((closure_set, next_qe_tags))
                            
        return ao_transitions, q0_tags
        
    @staticmethod
    def draw_AO_ACAG_graph(ao_transitions, 
                        q0_tags,
                        lable_ACAG_map,
                        secret_states,
                        filename):
        """
        修改版 AO-ACAG 绘图：
        1. 每一个导致 AX 的动作都指向一个独立的 AX 终点节点。
        2. 包含秘密状态且不导致 AX 的节点标绿。
        """
        dot = graphviz.Digraph(comment='AO-ACAG System', format='svg')
        
        dot.attr(
            rankdir='TB',
            nodesep='0.3', 
            ranksep='0.4',
            fontname='serif',
            fontsize='11',
            splines='spline',
            forcelabels='true'
        )

        def get_id(obj):
            return hex(hash(str(obj)) & 0xffffffff)

        def format_tags(tags):
            if tags == 'AX': return 'AX'
            return "{" + ",".join(tags) + "}"

        # 建立标签到原始状态的逆映射，用于判定 secret_states
        tag_to_state = {v: k for k, v in lable_ACAG_map.items()}

        visited_nodes = set()
        ax_counter = 0 # 用于生成唯一的 AX 节点 ID

        # --- 1. 初始箭头 ---
        dot.node('start_node', label='', shape='none', width='0', height='0')
        dot.edge('start_node', get_id(q0_tags), arrowsize='0.6')

        # --- 2. 遍历转移 ---
        for (qa_info, t_sigma), next_qe_tags in ao_transitions.items():
            curr_qe_tags, o_sigma = qa_info
            
            qe_id = get_id(curr_qe_tags)
            qa_id = get_id(qa_info)

            # A. 绘制环境聚类节点 (Qe)
            if qe_id not in visited_nodes:
                # 判定是否包含秘密状态
                has_secret = False
                for tag in curr_qe_tags:
                    orig_state = tag_to_state.get(tag)
                    if orig_state and len(orig_state) >= 2:
                        # 检查 xi_A (orig_state[1]) 是否是秘密集的子集
                        if len(orig_state[1]) > 0 and orig_state[1].issubset(secret_states):
                            has_secret = True
                            break
                
                fill_c, color_c = '#F8F9FA', '#333333'
                # 如果包含秘密且不是 AX，标绿
                if has_secret and curr_qe_tags != 'AX':
                    fill_c, color_c = '#F0FDF4', '#166534'

                node_html = f'<<B>{format_tags(curr_qe_tags)}</B>>'
                dot.node(qe_id, label=node_html, shape='rectangle', style='filled, rounded', 
                        fillcolor=fill_c, color=color_c, margin='0.05,0.02', width='0', height='0')
                visited_nodes.add(qe_id)

            # B. 绘制攻击决策点 (Qa)
            if qa_id not in visited_nodes:
                dot.node(qa_id, label='', shape='circle', width='0.08', height='0.08', 
                        fixedsize='true', fillcolor='black', style='filled', color='none')
                visited_nodes.add(qa_id)

            # C. 绘制边与目标节点
            # Qe -> Qa (实线)
            dot.edge(qe_id, qa_id, label=f" {o_sigma} ", style='solid', color='black', arrowsize='0.6')

            # Qa -> Next (虚线蓝色)
            if next_qe_tags == 'AX':
                # 每一个 AX 动作指向一个独立的节点
                unique_ax_id = f"ax_node_{ax_counter}"
                ax_counter += 1
                dot.node(unique_ax_id, label='<<B>AX</B>>', shape='rectangle', 
                        style='filled, rounded', fillcolor='#FFF1F2', color='#9F1239',
                        fontname='serif', fontsize='10')
                dot.edge(qa_id, unique_ax_id, label=f" {t_sigma} ", 
                        style='dashed', color='#2563EB', fontcolor='#2563EB', arrowsize='0.6')
            else:
                next_id = get_id(next_qe_tags)
                if next_id not in visited_nodes:
                    # 重复上面的 Qe 绘制逻辑（判定绿色）
                    is_next_secret = False
                    for tag in next_qe_tags:
                        orig_state = tag_to_state.get(tag)
                        if orig_state and len(orig_state) >= 2:
                            if len(orig_state[1]) > 0 and orig_state[1].issubset(secret_states):
                                is_next_secret = True; break
                    
                    n_fill, n_col = ('#F0FDF4', '#166534') if is_next_secret else ('#F8F9FA', '#333333')
                    
                    dot.node(next_id, label=f'<<B>{format_tags(next_qe_tags)}</B>>', 
                            shape='rectangle', style='filled, rounded', 
                            fillcolor=n_fill, color=n_col, margin='0.05,0.02')
                    visited_nodes.add(next_id)
                
                dot.edge(qa_id, next_id, label=f" {t_sigma} ", 
                        style='dashed', color='#2563EB', fontcolor='#2563EB', arrowsize='0.6')

        dot.render(filename, cleanup=True)
        return dot
    