from collections import deque
import graphviz

class GraphSimplyfier:
    @staticmethod
    def draw_simplified_ACAG_graph(all_ACAG_transition, 
                                   initial_env_state, 
                                   secret_states,
                                   labled_unobservable_reachable_supervisor, 
                                   labled_unobservable_reachable_attacker,
                                   Sigma_oS, # 增加：监督者可观事件集
                                   Sigma_oA, # 增加：攻击者可观事件集
                                   filename,
                                   max_nodes=30):
        """
        原函数逻辑完全保留，仅在末尾添加图例绘制逻辑
        """

        if isinstance(all_ACAG_transition, tuple):
            all_ACAG_transition = all_ACAG_transition[0]

        dot = graphviz.Digraph(comment='ACAG Compact', format='svg', engine='dot')
        
        dot.attr(
            rankdir='TB',
            nodesep='0.3', ranksep='0.5',
            fontname='serif', fontsize='14',
            splines='true'
        )

        sup_val_to_label = {v: k for k, v in labled_unobservable_reachable_supervisor.items()}
        atk_val_to_label = {v: k for k, v in labled_unobservable_reachable_attacker.items()}

        def get_id(state):
            return hex(hash(state) & 0xffffffff)

        # --- 颜色判断辅助逻辑 ---
        def get_edge_color(event):
            is_sup_obs = event in Sigma_oS
            is_atk_obs = event in Sigma_oA
            if is_atk_obs and not is_sup_obs:
                return '#EF4444'  # 红色 (仅攻击者)
            if is_sup_obs and not is_atk_obs:
                return '#22C55E'  # 绿色 (仅监督者)
            if is_sup_obs and is_atk_obs:
                return '#3B82F6'  # 蓝色 (双可观)
            return '#4B5563'      # 深灰色 (皆不可见)

        adj_map = {}
        for (curr, event), next_s in all_ACAG_transition.items():
            adj_map.setdefault(curr, []).append((event, next_s))

        real_start_node = None
        for (curr, _) in all_ACAG_transition.keys():
            if len(curr) == 4 and all(e1 == e2 for e1, e2 in zip(curr, initial_env_state)):
                real_start_node = curr; break
        if not real_start_node: return

        # --- BFS 逻辑 (保持不变) ---
        queue = deque([real_start_node])
        visited = {real_start_node}
        ye_map = {real_start_node: "ye0"}
        ye_count = 1
        nodes_to_draw = [real_start_node]
        edges_to_draw = []
        truncated_ye = set()

        while queue:
            curr = queue.popleft()
            if len(curr) == 4:
                if ye_count >= max_nodes:
                    if curr in adj_map: truncated_ye.add(curr)
                    continue
                for event, nxt_ya in adj_map.get(curr, []):
                    has_valid_next_ye = False
                    temp_next_ye_list = []
                    for obs, nxt_ye in adj_map.get(nxt_ya, []):
                        if nxt_ye in visited:
                            has_valid_next_ye = True
                            temp_next_ye_list.append((obs, nxt_ye))
                        elif ye_count < max_nodes:
                            ye_count += 1
                            ye_map[nxt_ye] = f"ye{ye_count-1}"
                            visited.add(nxt_ye)
                            queue.append(nxt_ye)
                            nodes_to_draw.append(nxt_ye)
                            has_valid_next_ye = True
                            temp_next_ye_list.append((obs, nxt_ye))
                    
                    if has_valid_next_ye:
                        if nxt_ya not in nodes_to_draw: nodes_to_draw.append(nxt_ya)
                        edges_to_draw.append((curr, event, nxt_ya))
                        for obs, valid_ye in temp_next_ye_list:
                            edges_to_draw.append((nxt_ya, obs, valid_ye))
                    else:
                        truncated_ye.add(curr)

        # --- 3. 绘制节点 (保持不变) ---
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

                ye_tag = ye_map.get(node, "")
                ye_row = f'<TR><TD ALIGN="CENTER" BORDER="0" CELLPADDING="0"><FONT POINT-SIZE="12"><B>{ye_tag}</B></FONT></TD></TR>' if ye_tag else ""
                box_row = f'<TR><TD BORDER="1" STYLE="ROUNDED" BGCOLOR="{fill_c}" COLOR="{color_c}" CELLPADDING="4" PORT="box"><B><FONT POINT-SIZE="14">{s_tag}, {a_tag}, {x}, {z}</FONT></B></TD></TR>'
                ellipsis_row = "<TR><TD BORDER='0' CELLPADDING='0' ALIGN='CENTER'><FONT POINT-SIZE='16'>...</FONT></TD></TR>" if node in truncated_ye and not (is_ax or is_success) else ""

                node_label = f'''<
                    <TABLE BORDER="0" CELLBORDER="0" CELLSPACING="0" CELLPADDING="0" FIXEDSIZE="FALSE">
                        {ye_row} {box_row} {ellipsis_row}
                    </TABLE>>'''
                dot.node(nid, label=node_label, shape='none', margin='0')
            else:
                dot.node(nid, label='', shape='circle', width='0.1', height='0.1', 
                         fillcolor='white', style='filled', color='black', penwidth='0.8')

        # --- 4. 绘制连边 (保持不变) ---
        for src, event, nxt in edges_to_draw:
            src_id = get_id(src)
            nxt_id = get_id(nxt)
            tail = f"{src_id}:box" if len(src) == 4 else src_id
            head = f"{nxt_id}:box" if len(nxt) == 4 else nxt_id
            is_env_output = (len(src) == 4)
            e_style = 'solid' if is_env_output else 'dashed'
            e_color = get_edge_color(event) if is_env_output else '#666666'
            e_text = str(event) if event != 'empty' else 'ε'
            dot.edge(tail, head, label=f"<<B> {e_text} </B>>", 
                     style=e_style, color=e_color, fontcolor=e_color,
                     fontsize='13', arrowsize='0.6')

        # --- 新增图例逻辑：确保在最右上角 ---
        with dot.subgraph(name='cluster_legend') as l:
            l.attr(label='', fontsize='12', color='lightgrey', style='rounded')
            # 使用 HTML 格式创建更精美的图例表格
            legend_html = '''<
                <TABLE BORDER="0" CELLBORDER="0" CELLSPACING="4" CELLPADDING="2">
                    <TR>
                        <TD BORDER="1" BGCOLOR="#F0FDF4" COLOR="#166534" WIDTH="20"></TD>
                        <TD ALIGN="LEFT"><FONT POINT-SIZE="12">Attacker-Exposed States</FONT></TD>
                    </TR>
                    <TR>
                        <TD BORDER="1" BGCOLOR="#FFF1F2" COLOR="#9F1239" WIDTH="20"></TD>
                        <TD ALIGN="LEFT"><FONT POINT-SIZE="12">CS-Detected States</FONT></TD>
                    </TR>
                </TABLE>>'''
            l.node('legend_node', label=legend_html, shape='none')

        dot.render(filename, cleanup=True)
        return dot, ye_map

    @staticmethod
    def draw_simplified_AO_ACAG_graph(ao_transitions, q0_tags, lable_ACAG_map, secret_states, filename, max_nodes=35):
        """
        """
        import graphviz
        from collections import deque
        dot = graphviz.Digraph(comment='AO-ACAG Compact Style', format='svg', strict=True)
        dot.attr(rankdir='TB', nodesep='0.2', ranksep='0.5', fontname='serif', fontsize='14')

        def get_id(obj): return hex(hash(str(obj)) & 0xffffffff)
        def format_tags(tags): return 'AX' if tags == 'AX' else "{" + ",".join(sorted(list(tags))) + "}"

        tag_to_state = {v: k for k, v in lable_ACAG_map.items()}
        queue = deque([q0_tags])
        visited_qe = {q0_tags}
        qe_map = {q0_tags: "qe0"}
        qe_count = 1
        ax_count = 0
        nodes_to_draw_qe = []
        nodes_to_draw_qa = set()
        edges_to_draw = [] 
        truncated_qe = set()
        qe_to_qa_edges = set() 
        adj_map = {}

        for (qa_info, t_sigma), next_qe in ao_transitions.items():
            curr_qe, o_sigma = qa_info
            adj_map.setdefault(curr_qe, []).append((o_sigma, t_sigma, next_qe))

        while queue:
            curr_qe = queue.popleft()
            nodes_to_draw_qe.append(curr_qe)
            if qe_count >= max_nodes:
                if curr_qe in adj_map: truncated_qe.add(curr_qe)
                continue
            for o_sigma, t_sigma, next_qe in adj_map.get(curr_qe, []):
                qa_id = get_id((curr_qe, o_sigma))
                if (get_id(curr_qe), qa_id, o_sigma) not in qe_to_qa_edges:
                    edges_to_draw.append((f"{get_id(curr_qe)}:box", qa_id, o_sigma, 'solid'))
                    qe_to_qa_edges.add((get_id(curr_qe), qa_id, o_sigma))
                nodes_to_draw_qa.add(qa_id)
                if next_qe == 'AX':
                    ax_id = f"ax_{ax_count}"; ax_count += 1
                    label_ax = f'<<TABLE BORDER="0" CELLBORDER="0" CELLSPACING="0"><TR><TD BORDER="1" STYLE="ROUNDED" BGCOLOR="#FFF1F2" COLOR="#9F1239" CELLPADDING="4" PORT="box"><B><FONT POINT-SIZE="14">AX</FONT></B></TD></TR></TABLE>>'
                    dot.node(ax_id, label=label_ax, shape='none')
                    edges_to_draw.append((qa_id, f"{ax_id}:box", t_sigma, 'dashed'))
                else:
                    if next_qe not in visited_qe:
                        if qe_count < max_nodes:
                            qe_map[next_qe] = f"qe{qe_count}"; qe_count += 1
                            visited_qe.add(next_qe)
                            queue.append(next_qe)
                        else:
                            truncated_qe.add(curr_qe)
                    edges_to_draw.append((qa_id, f"{get_id(next_qe)}:box", t_sigma, 'dashed'))

        for qe_tag in nodes_to_draw_qe:
            nid = get_id(qe_tag)
            has_secret = any(tag_to_state.get(tag, ([],[]))[1].issubset(secret_states) for tag in qe_tag)
            fill_c, color_c = ('#F0FDF4', '#166534') if has_secret else ('#F8F9FA', '#333333')
            qe_label = qe_map.get(qe_tag, "")
            qe_row = f'<TR><TD ALIGN="LEFT" BORDER="0" CELLPADDING="1"><FONT POINT-SIZE="14"><B>{qe_label}</B></FONT></TD></TR>' if qe_label else ""
            ellipsis_row = "<TR><TD BORDER='0' CELLPADDING='0'><FONT POINT-SIZE='18'>...</FONT></TD></TR>" if qe_tag in truncated_qe else ""
            label_html = f'''<
                <TABLE BORDER="0" CELLBORDER="0" CELLSPACING="0" CELLPADDING="0">
                    {qe_row}
                    <TR><TD BORDER="1" STYLE="ROUNDED" BGCOLOR="{fill_c}" COLOR="{color_c}" CELLPADDING="4" PORT="box"><FONT POINT-SIZE="14"><B>{format_tags(qe_tag)}</B></FONT></TD></TR>
                    {ellipsis_row}
                </TABLE>>'''
            dot.node(nid, label=label_html, shape='none')

        for qa_id in nodes_to_draw_qa:
            dot.node(qa_id, label='', shape='circle', width='0.1', height='0.1', fillcolor='white', style='filled', color='black', penwidth='0.7')

        for src, dst, txt, style in edges_to_draw:
            e_color = '#2563EB' if style == 'dashed' else '#333333'
            dot.edge(src, dst, label=f"<<B> {txt} </B>>", style=style, color=e_color, fontcolor=e_color, fontsize='14', arrowsize='0.5', penwidth='1.0')

         # --- 新增图例逻辑：确保在最右上角 ---
        with dot.subgraph(name='cluster_legend') as l:
            l.attr(label='', fontsize='12', color='lightgrey', style='rounded')
            # 使用 HTML 格式创建更精美的图例表格
            legend_html = '''<
                <TABLE BORDER="0" CELLBORDER="0" CELLSPACING="4" CELLPADDING="2">
                    <TR>
                        <TD BORDER="1" BGCOLOR="#F0FDF4" COLOR="#166534" WIDTH="20"></TD>
                        <TD ALIGN="LEFT"><FONT POINT-SIZE="12">Attacker-Exposed States</FONT></TD>
                    </TR>
                    <TR>
                        <TD BORDER="1" BGCOLOR="#FFF1F2" COLOR="#9F1239" WIDTH="20"></TD>
                        <TD ALIGN="LEFT"><FONT POINT-SIZE="12">CS-Detected States</FONT></TD>
                    </TR>
                </TABLE>>'''
            l.node('legend_node', label=legend_html, shape='none')
        dot.render(filename, cleanup=True)
        return dot, qe_map

    @staticmethod
    def draw_simplified_pruned_AO_ACAG_graph(pruned_transitions, q0_tags, lable_ACAG_map, secret_states, qe_map, filename_prefix):
        import graphviz
        from collections import deque
        
        # --- 1. 样式与辅助工具 ---
        tag_to_state = {v: k for k, v in lable_ACAG_map.items()}
        
        def check_has_secret(tags):
            for tag in tags:
                orig_state = tag_to_state.get(tag)
                if orig_state and len(orig_state) >= 2:
                    xi_A = orig_state[1]
                    if xi_A.issubset(secret_states): return True
            return False

        def get_node_style(tags, is_external=False):
            if is_external: return '#FFFFFF', '#A0A0A0'
            if check_has_secret(tags): return '#F0FDF4', '#166534'
            return '#F8F9FA', '#333333'

        def get_id(obj): return hex(hash(str(obj)) & 0xffffffff)
        def format_tags(tags): return "{" + ",".join(sorted(list(tags))) + "}"
        
        def get_qe_row(tags):
            label = qe_map.get(tags, "")
            return f'<TR><TD ALIGN="LEFT" BORDER="0" CELLPADDING="1"><FONT POINT-SIZE="14" COLOR="black"><B>{label}</B></FONT></TD></TR>' if label else ""

        # --- 2. 寻找 SCC ---
        adj = {}
        all_qe = set()
        for (qa_info, t_sigma), next_qe in pruned_transitions.items():
            curr_qe, o_sigma = qa_info
            all_qe.add(curr_qe)
            if next_qe != 'AX':
                all_qe.add(next_qe)
                adj.setdefault(curr_qe, set()).add(next_qe)

        def find_sccs(nodes, adjacency):
            dfn, low, stack, in_stack, sccs, timer = {}, {}, [], set(), [], 0
            def visit(u):
                nonlocal timer
                dfn[u] = low[u] = timer; timer += 1
                stack.append(u); in_stack.add(u)
                for v in adjacency.get(u, []):
                    if v not in dfn:
                        visit(v); low[u] = min(low[u], low[v])
                    elif v in in_stack:
                        low[u] = min(low[u], dfn[v])
                if low[u] == dfn[u]:
                    scc = []
                    while True:
                        node = stack.pop(); in_stack.remove(node); scc.append(node)
                        if node == u: break
                    sccs.append(scc)
            for n in nodes:
                if n not in dfn: visit(n)
            return sccs

        raw_sccs = find_sccs(all_qe, adj)
        node_to_scc_id = {}
        scc_contents = {}
        scc_idx = 0
        for scc in sorted(raw_sccs, key=len, reverse=True):
            if len(scc) > 1:
                sid = f"SCC{scc_idx}"
                scc_contents[sid] = scc
                for node in scc: node_to_scc_id[node] = sid
                scc_idx += 1

        # --- 3. 绘制主图 (Main Graph) ---
        main_dot = graphviz.Digraph(comment='Main', format='svg', strict=True)
        main_dot.attr(rankdir='TB', nodesep='0.2', ranksep='0.4', fontname='serif', fontsize='14')
        
        drawn_main_nodes = set()
        ax_needed = False
        
        for qe in all_qe:
            u_repr = node_to_scc_id.get(qe, qe)
            if u_repr in drawn_main_nodes: continue
            nid = get_id(u_repr)
            if isinstance(u_repr, str) and u_repr.startswith("SCC"):
                is_sec_scc = any(check_has_secret(node) for node in scc_contents[u_repr])
                fill_c, color_c = ('#F0FDF4', '#166534') if is_sec_scc else ('#EFF6FF', '#1D4ED8')
                main_dot.node(nid, label=f"<<B><FONT POINT-SIZE='14'>{u_repr}</FONT></B>>", shape='doubleoctagon', style='filled', fillcolor=fill_c, color=color_c)
            else:
                f_c, c_c = get_node_style(u_repr)
                lbl = f'<<TABLE BORDER="0" CELLBORDER="0" CELLSPACING="0" CELLPADDING="0">{get_qe_row(u_repr)}<TR><TD BORDER="1" STYLE="ROUNDED" BGCOLOR="{f_c}" COLOR="{c_c}" CELLPADDING="2" PORT="box"><FONT POINT-SIZE="14"><B>{format_tags(u_repr)}</B></FONT></TD></TR></TABLE>>'
                main_dot.node(nid, label=lbl, shape='none')
            drawn_main_nodes.add(u_repr)

        # 绘制连边
        for (qa_info, t_sigma), next_qe in pruned_transitions.items():
            curr_qe, o_sigma = qa_info
            u_repr = node_to_scc_id.get(curr_qe, curr_qe)
            v_repr = node_to_scc_id.get(next_qe, next_qe) if next_qe != 'AX' else 'AX'
            
            # --- 核心逻辑修改：过滤 SCC 节点的自环，保留普通节点的自环 ---
            is_u_scc = isinstance(u_repr, str) and u_repr.startswith("SCC")
            if u_repr == v_repr and is_u_scc:
                continue # 忽略 SCC 节点的自环
            
            qa_id = get_id((u_repr, o_sigma, v_repr))
            if qa_id not in drawn_main_nodes:
                main_dot.node(qa_id, label='', shape='circle', width='0.1', fillcolor='white', style='filled')
                drawn_main_nodes.add(qa_id)
            
            src = get_id(u_repr) if is_u_scc else f"{get_id(u_repr)}:box"
            main_dot.edge(src, qa_id, label=f"<<FONT POINT-SIZE='14'>{o_sigma}</FONT>>")
            
            if v_repr == 'AX':
                if not ax_needed:
                    main_dot.node('AX_REAL', label='<<TABLE BORDER="0" CELLBORDER="0" CELLSPACING="0"><TR><TD BORDER="1" STYLE="ROUNDED" BGCOLOR="#FFF1F2" COLOR="#9F1239" PORT="box"><B><FONT POINT-SIZE="14">AX</FONT></B></TD></TR></TABLE>>', shape='none')
                    ax_needed = True
                main_dot.edge(qa_id, 'AX_REAL:box', label=f"<<FONT POINT-SIZE='14'>{t_sigma}</FONT>>", style='dashed', color='#2563EB')
            else:
                dst = get_id(v_repr) if (isinstance(v_repr, str) and v_repr.startswith("SCC")) else f"{get_id(v_repr)}:box"
                main_dot.edge(qa_id, dst, label=f"<<FONT POINT-SIZE='14'>{t_sigma}</FONT>>", style='dashed', color='#2563EB')

        main_dot.render(f"{filename_prefix}_main", cleanup=True)

        # --- 4. SCC 子图绘制 (子图中依然保留所有细节) ---
        for sid, scc_nodes in scc_contents.items():
            sub_dot = graphviz.Digraph(comment=sid, engine='neato', strict=True)
            sub_dot.attr(overlap='scale', splines='curved', fontname='serif', sep='+8', esep='+4', K='0.8')
            node_set = set(scc_nodes)
            sub_drawn_nodes = set()

            def draw_sub_node(n, is_external=False):
                if n in sub_drawn_nodes: return
                nid = get_id(n)
                if n == 'AX':
                    sub_dot.node(nid, label='<<TABLE BORDER="0" CELLBORDER="0" CELLSPACING="0"><TR><TD BORDER="1" STYLE="ROUNDED" BGCOLOR="#FFF1F2" COLOR="#9F1239" PORT="box"><B><FONT POINT-SIZE="14">AX</FONT></B></TD></TR></TABLE>>', shape='none')
                else:
                    f_c, c_c = get_node_style(n, is_external)
                    lbl = f'<<TABLE BORDER="0" CELLBORDER="0" CELLSPACING="0" CELLPADDING="0">{get_qe_row(n)}<TR><TD BORDER="1" STYLE="ROUNDED" BGCOLOR="{f_c}" COLOR="{c_c}" CELLPADDING="3" PORT="box"><FONT POINT-SIZE="14"><B>{format_tags(n)}</B></FONT></TD></TR></TABLE>>'
                    sub_dot.node(nid, label=lbl, shape='none')
                sub_drawn_nodes.add(n)

            for (qa_info, t_sigma), next_qe in pruned_transitions.items():
                curr_qe, o_sigma = qa_info
                if (curr_qe in node_set or next_qe in node_set):
                    draw_sub_node(curr_qe, (curr_qe not in node_set))
                    draw_sub_node(next_qe, (next_qe not in node_set and next_qe != 'AX'))
                    
                    qa_sub_id = get_id((curr_qe, o_sigma, next_qe, sid))
                    sub_dot.node(qa_sub_id, label='', shape='circle', width='0.1', fillcolor='white', style='filled')
                    
                    is_internal = (curr_qe in node_set and next_qe in node_set)
                    edge_color = '#2563EB' if is_internal else '#999999'
                    e_len = '0.8' if is_internal else '1.2'
                    
                    sub_dot.edge(get_id(curr_qe)+":box", qa_sub_id, label=f"<<FONT POINT-SIZE='14'>{o_sigma}</FONT>>", color=edge_color, len=e_len)
                    sub_dot.edge(qa_sub_id, get_id(next_qe)+":box", label=f"<<FONT POINT-SIZE='14'>{t_sigma}</FONT>>", style='dashed', color=edge_color, len=e_len)

            sub_dot.render(f"{filename_prefix}_{sid}", cleanup=True)
        
        return main_dot