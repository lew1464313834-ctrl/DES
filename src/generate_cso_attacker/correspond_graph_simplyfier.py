from collections import deque
import graphviz
class GraphSimplyfier:

    @staticmethod
    def draw_paper_simplified_ACAG(all_ACAG_transition, 
                                               initial_env_state, 
                                               secret_states,
                                               sup_labels, 
                                               atk_labels,
                                               max_full_depth=2, 
                                               filename='simplified_ACAG'):

        sup_val_to_label = {v: k for k, v in sup_labels.items()}
        atk_val_to_label = {v: k for k, v in atk_labels.items()}

        def is_success(s):
            return len(s) == 4 and len(s[1]) > 0 and s[1].issubset(secret_states)
        def is_ax(s):
            return len(s) == 4 and (s[0] == frozenset({'AX'}) or s[2] == 'z_det')

        # 1. 构建邻接表
        adj_map = {}
        for (curr, event), next_s in all_ACAG_transition.items():
            if curr not in adj_map: adj_map[curr] = []
            adj_map[curr].append((event, next_s))

        # 2. 识别关键路径节点
        critical_nodes = set()
        def find_critical_nodes(target_func):
            nodes = set()
            queue = deque([(initial_env_state, [initial_env_state])])
            while queue:
                curr, path = queue.popleft()
                if target_func(curr):
                    nodes.update(path)
                if len(path) < 10: 
                    for _, next_s in adj_map.get(curr, []):
                        queue.append((next_s, path + [next_s]))
            return nodes

        critical_nodes.update(find_critical_nodes(is_success))
        critical_nodes.update(find_critical_nodes(is_ax))

        # 3. 绘图初始化
        dot = graphviz.Digraph(format='svg')
        dot.attr(rankdir='LR', nodesep='0.4', ranksep='0.7', fontname='Times-Roman', fontsize='12')
        
        # --- 核心改进：强化省略号节点的显著性 ---
        dot.node('ellipsis', 
                 label='...', 
                 shape='rectangle', 
                 style='dashed, rounded', 
                 color='#64748b',      # 深灰色边框
                 fontcolor='#475569',  # 深灰色文字
                 penwidth='2.0',       # 加粗边框
                 width='0.6', 
                 height='0.4')

        visited_nodes = set()
        drawn_edges = set()
        handled_omissions = set()

        queue = deque([(initial_env_state, 0)])
        visited_nodes.add(initial_env_state)

        while queue:
            curr, depth = queue.popleft()
            curr_id = str(hash(curr))

            # 绘制当前节点 (Ye 或 Ya)
            if len(curr) == 4:
                s_tag = sup_val_to_label.get(curr[0], "AX" if curr[0] == frozenset({'AX'}) else "?")
                a_tag = atk_val_to_label.get(curr[1], "?")
                label = f"<{s_tag},{a_tag},{curr[3]},{curr[2]}>"
                
                fill, border, pen = ('#DCFCE7', '#166534', '2.5') if is_success(curr) else \
                                   (('#FFE4E6', '#9F1239', '2.5') if is_ax(curr) else ('#F8F9FA', '#333333', '1.2'))
                dot.node(curr_id, label=label, shape='box', style='filled,rounded', 
                         fillcolor=fill, color=border, penwidth=pen)
            else:
                dot.node(curr_id, label='', shape='circle', width='0.12', style='filled', fillcolor='#0F172A')

            # 遍历子节点
            if curr in adj_map:
                for event, next_s in adj_map[curr]:
                    should_draw = (depth < max_full_depth) or (next_s in critical_nodes)
                    
                    if should_draw:
                        next_id = str(hash(next_s))
                        if (curr_id, next_id) not in drawn_edges:
                            is_atk = (len(curr) == 5)
                            style = 'dashed' if is_atk else 'solid'
                            color = '#2563EB' if is_atk else '#000000' # 蓝色虚线 vs 黑色实线
                            edge_w = '1.5' if is_atk else '1.2'
                            dot.edge(curr_id, next_id, label=f" {event} ", 
                                     style=style, color=color, penwidth=edge_w)
                            drawn_edges.add((curr_id, next_id))
                        
                        if next_s not in visited_nodes:
                            visited_nodes.add(next_s)
                            queue.append((next_s, depth + 1))
                    else:
                        # --- 核心改进：增强省略路径的可见性 ---
                        if curr_id not in handled_omissions:
                            dot.edge(curr_id, 'ellipsis', 
                                     style='dotted', 
                                     color='#64748b',     # 调深颜色
                                     penwidth='1.5',      # 增加线宽
                                     arrowhead='onormal', # 使用空心三角箭头区分
                                     arrowsize='0.8')
                            handled_omissions.add(curr_id)

        # 初始箭头
        dot.node('start', label='', shape='none')
        dot.edge('start', str(hash(initial_env_state)), penwidth='1.5')

        dot.render(filename, cleanup=True)
        return dot