from collections import deque
import graphviz
class GraphSimplyfier:
    @staticmethod
    def draw_simplified_ACAG_graph(all_ACAG_transition, 
                                   initial_env_state, 
                                   secret_states,
                                   labled_unobservable_reachable_supervisor, 
                                   labled_unobservable_reachable_attacker,
                                   filename,
                                   max_nodes=30):
        """
        修正版：严格防止孤立攻击节点，确保路径完整性。
        """
        if isinstance(all_ACAG_transition, tuple):
            all_ACAG_transition = all_ACAG_transition[0]

        dot = graphviz.Digraph(comment='ACAG Compact', format='svg', engine='dot')
        
        # --- 1. 布局优化 ---
        dot.attr(
            rankdir='TB',
            nodesep='0.25',
            ranksep='0.35',
            fontname='serif',
            fontsize='9',
            newrank='true',
            splines='line'
        )

        sup_val_to_label = {v: k for k, v in labled_unobservable_reachable_supervisor.items()}
        atk_val_to_label = {v: k for k, v in labled_unobservable_reachable_attacker.items()}

        def get_id(state):
            return hex(hash(state) & 0xffffffff)

        adj_map = {}
        for (curr, event), next_s in all_ACAG_transition.items():
            adj_map.setdefault(curr, []).append((event, next_s))

        # 查找初始节点
        real_start_node = None
        for (curr, _) in all_ACAG_transition.keys():
            if len(curr) == 4 and all(e1 == e2 for e1, e2 in zip(curr, initial_env_state)):
                real_start_node = curr; break
        if not real_start_node: return

        # --- 2. 改进的 BFS：确保 Ye -> Ya -> Ye 的完整性 ---
        queue = deque([real_start_node])
        visited = {real_start_node}
        ye_map = {real_start_node: "ye0"}
        ye_count = 1
        
        nodes_to_draw = [real_start_node]
        edges_to_draw = []
        truncated_ye = set()

        while queue:
            curr = queue.popleft()
            
            # 如果当前是环境节点，且已经达到上限，标记截断并跳过其后继 Ya 节点的生成
            if len(curr) == 4:
                if ye_count >= max_nodes:
                    if curr in adj_map:
                        truncated_ye.add(curr)
                    continue  # 关键点：不再处理该 Ye 节点发出的任何 Ya
                
                # 尝试展开当前 Ye 节点的后继 Ya
                for event, nxt_ya in adj_map.get(curr, []):
                    # 检查该 Ya 是否有至少一个后继 Ye 可以被绘制
                    has_valid_next_ye = False
                    temp_next_ye_list = []
                    
                    for obs, nxt_ye in adj_map.get(nxt_ya, []):
                        if nxt_ye in visited:
                            has_valid_next_ye = True
                            temp_next_ye_list.append((obs, nxt_ye))
                        elif ye_count < max_nodes:
                            # 发现新的 Ye，且未超过上限，允许展开
                            ye_count += 1
                            ye_map[nxt_ye] = f"ye{ye_count-1}"
                            visited.add(nxt_ye)
                            queue.append(nxt_ye)
                            nodes_to_draw.append(nxt_ye)
                            has_valid_next_ye = True
                            temp_next_ye_list.append((obs, nxt_ye))

                    # 只有当 Ya 能通向至少一个已存在或新创建的 Ye 时，才绘制该 Ya 及其连线
                    if has_valid_next_ye:
                        if nxt_ya not in nodes_to_draw:
                            nodes_to_draw.append(nxt_ya)
                        edges_to_draw.append((curr, event, nxt_ya))
                        for obs, valid_ye in temp_next_ye_list:
                            edges_to_draw.append((nxt_ya, obs, valid_ye))
                    else:
                        # 如果这个 Ya 无法通向任何有效的下一层 Ye，则当前 Ye 应当被视为截断
                        truncated_ye.add(curr)

        # --- 3. 绘制节点：引入 PORT 锚点 ---
        for node in nodes_to_draw:
            nid = get_id(node)
            if len(node) == 4:
                xi_S, xi_A, z, x = node
                s_tag = sup_val_to_label.get(xi_S, "AX" if xi_S == frozenset({'AX'}) else "?")
                a_tag = atk_val_to_label.get(xi_A, "?")
                is_ax = (xi_S == 'AX' or xi_S == frozenset({'AX'}) or z == 'z_det')
                is_success = (len(xi_A) > 0 and xi_A.issubset(secret_states))
                
                fill_c, color_c = ('#F8F9FA', '#333333')
                if is_ax: fill_c, color_c = ('#FFF1F2', '#9F1239')
                elif is_success: fill_c, color_c = ('#F0FDF4', '#166534')

                # HTML 布局：PORT="m" 用于锚定连线，防止连线指向省略号
                if node in truncated_ye and not (is_ax or is_success):
                    node_label = f'''<
                        <TABLE BORDER="0" CELLBORDER="0" CELLSPACING="0" CELLPADDING="0">
                            <TR><TD BORDER="1" STYLE="ROUNDED" BGCOLOR="{fill_c}" COLOR="{color_c}" CELLPADDING="2" PORT="m"><B>{s_tag}, {a_tag}, {x}, {z}</B></TD></TR>
                            <TR><TD CELLPADDING="0"><FONT POINT-SIZE="16">...</FONT></TD></TR>
                        </TABLE>>'''
                else:
                    node_label = f'''<
                        <TABLE BORDER="0" CELLBORDER="0" CELLSPACING="0" CELLPADDING="0">
                            <TR><TD BORDER="1" STYLE="ROUNDED" BGCOLOR="{fill_c}" COLOR="{color_c}" CELLPADDING="2" PORT="m"><B>{s_tag}, {a_tag}, {x}, {z}</B></TD></TR>
                        </TABLE>>'''
                
                dot.node(nid, label=node_label, shape='none', xlabel=ye_map.get(node, ""), margin='0')
            else:
                # 攻击节点 Ya：空心圆
                dot.node(nid, label='', shape='circle', width='0.08', height='0.08', 
                         fillcolor='white', style='filled', color='black', penwidth='0.7')

        # --- 4. 绘制连边：使用 :m 语法指向端口 ---
        for src, event, nxt in edges_to_draw:
            src_id = get_id(src)
            nxt_id = get_id(nxt)
            
            # 使用 :m 确保连线贴合状态框，忽略下方的省略号
            tail = f"{src_id}:m" if len(src) == 4 else src_id
            head = f"{nxt_id}:m" if len(nxt) == 4 else nxt_id
            
            is_from_ya = (len(src) == 6)
            e_style = 'dashed' if is_from_ya else 'solid'
            e_text = str(event) if event != 'empty' else 'ε'
            
            dot.edge(tail, head, label=f" {e_text} ", 
                     style=e_style, color='#444444', fontsize='8', arrowsize='0.4')

        # 起始箭头
        dot.node('start', label='', shape='none', width='0', height='0')
        dot.edge('start', f"{get_id(real_start_node)}:m", arrowsize='0.5')

        dot.render(filename, cleanup=True)
        return dot, ye_map