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


    @staticmethod
    def draw_simplified_AO_ACAG_graph(ao_transitions, 
                                      q0_tags,
                                      lable_ACAG_map,
                                      secret_states,
                                      filename,
                                      max_nodes=35):
        import graphviz
        from collections import deque

        # strict=True 自动处理完全重合的边，确保同一个事件只有一个箭头
        dot = graphviz.Digraph(comment='AO-ACAG Compact Style', format='svg', strict=True)
        
        # --- 1. 布局优化：极致收窄宽度，增加纵向伸缩 ---
        dot.attr(
            rankdir='TB',
            nodesep='0.15',    # 水平间距极小化
            ranksep='0.35',    # 垂直间距紧凑
            fontname='serif',
            fontsize='9',
            splines='polyline', # 折线布局最节省横向空间
            concentrate='true'  # 聚合并行边
        )

        def get_id(obj):
            return hex(hash(str(obj)) & 0xffffffff)

        def format_tags(tags):
            if tags == 'AX': return 'AX'
            return "{" + ",".join(sorted(list(tags))) + "}"

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
                # 以 (当前节点, 观测事件) 为唯一标识，确保输出弧唯一
                qa_id = get_id((curr_qe, o_sigma))
                
                # A. 绘制 Qe -> Qa (观测弧)
                if (get_id(curr_qe), qa_id, o_sigma) not in qe_to_qa_edges:
                    edges_to_draw.append((f"{get_id(curr_qe)}:m", qa_id, o_sigma, 'solid'))
                    qe_to_qa_edges.add((get_id(curr_qe), qa_id, o_sigma))
                
                nodes_to_draw_qa.add(qa_id)

                # B. 绘制 Qa -> Next (决策弧)
                if next_qe == 'AX':
                    ax_id = f"ax_{ax_count}"; ax_count += 1
                    # 修复告警：在 HTML 中加入 PORT="m"
                    label_ax = f'<<TABLE BORDER="0" CELLBORDER="0" CELLSPACING="0"><TR><TD BORDER="1" STYLE="ROUNDED" BGCOLOR="#FFF1F2" COLOR="#9F1239" CELLPADDING="2" PORT="m"><B>AX</B></TD></TR></TABLE>>'
                    dot.node(ax_id, label=label_ax, shape='none')
                    edges_to_draw.append((qa_id, f"{ax_id}:m", t_sigma, 'dashed'))
                else:
                    if next_qe not in visited_qe:
                        if qe_count < max_nodes:
                            qe_map[next_qe] = f"qe{qe_count}"; qe_count += 1
                            visited_qe.add(next_qe)
                            queue.append(next_qe)
                        else:
                            truncated_qe.add(curr_qe)
                    edges_to_draw.append((qa_id, f"{get_id(next_qe)}:m", t_sigma, 'dashed'))

        # --- 2. 绘制 Qe 环境节点 ---
        for qe_tag in nodes_to_draw_qe:
            nid = get_id(qe_tag)
            has_secret = any(tag_to_state.get(tag, ([],[]))[1].issubset(secret_states) for tag in qe_tag)
            fill_c, color_c = ('#F0FDF4', '#166534') if has_secret else ('#F8F9FA', '#333333')
            
            label_html = f'''<
                <TABLE BORDER="0" CELLBORDER="0" CELLSPACING="0" CELLPADDING="0">
                    <TR><TD BORDER="1" STYLE="ROUNDED" BGCOLOR="{fill_c}" COLOR="{color_c}" CELLPADDING="2" PORT="m"><B>{format_tags(qe_tag)}</B></TD></TR>
                    {"<TR><TD><FONT POINT-SIZE='8'>...</FONT></TD></TR>" if qe_tag in truncated_qe else ""}
                </TABLE>>'''
            # 使用 xlabel 减小对布局宽度的影响
            dot.node(nid, label=label_html, shape='none', xlabel=f'<<FONT POINT-SIZE="8">{qe_map.get(qe_tag, "")}</FONT>>')

        # --- 3. 绘制 Qa 决策节点 (空心小圆点) ---
        for qa_id in nodes_to_draw_qa:
            dot.node(qa_id, label='', shape='circle', width='0.05', height='0.05', 
                     fillcolor='white', style='filled', color='black', penwidth='0.6')

        # --- 4. 连边 ---
        for src, dst, txt, style in edges_to_draw:
            e_color = '#2563EB' if style == 'dashed' else '#333333'
            dot.edge(src, dst, label=f" {txt} ", style=style, color=e_color, 
                     fontcolor=e_color, fontsize='8', arrowsize='0.35', penwidth='0.7')

        dot.render(filename, cleanup=True)
        return dot, qe_map
    
    @staticmethod
    def draw_simplified_pruned_AO_ACAG_graph(pruned_transitions, 
                                            q0_tags,
                                            lable_ACAG_map,
                                            secret_states,
                                            qe_map,
                                            filename_prefix):


        # --- 1. 内部样式辅助函数 ---
        tag_to_state = {v: k for k, v in lable_ACAG_map.items()}
        
        def check_has_secret(tags):
            for tag in tags:
                orig_state = tag_to_state.get(tag)
                if orig_state and len(orig_state) >= 2:
                    xi_A = orig_state[1]
                    if xi_A.issubset(secret_states):
                        return True
            return False

        def get_node_style(tags, is_external=False):
            if is_external:
                return '#FFFFFF', '#A0A0A0' # 外部节点：白底灰框
            if check_has_secret(tags):
                return '#F0FDF4', '#166534' # 秘密节点：绿底绿框
            return '#F8F9FA', '#333333'     # 普通节点：灰底黑框

        def get_id(obj):
            return hex(hash(str(obj)) & 0xffffffff)

        def format_tags(tags):
            return "{" + ",".join(sorted(list(tags))) + "}"

        def get_xlabel(tags):
            label = qe_map.get(tags, "")
            return f'<<FONT POINT-SIZE="8">{label}</FONT>>' if label else ""

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
        # 针对双栏论文优化的紧凑尺寸
        main_dot.attr(rankdir='TB', size='3.5,20!', ratio='compress', 
                     nodesep='0.1', ranksep='0.3', fontname='serif', fontsize='9')

        drawn_main_nodes = set()
        ax_needed = False
        
        for qe in all_qe:
            u_repr = node_to_scc_id.get(qe, qe)
            if u_repr in drawn_main_nodes: continue
            
            nid = get_id(u_repr)
            if isinstance(u_repr, str) and u_repr.startswith("SCC"):
                is_sec_scc = any(check_has_secret(node) for node in scc_contents[u_repr])
                fill_c, color_c = ('#F0FDF4', '#166534') if is_sec_scc else ('#EFF6FF', '#1D4ED8')
                main_dot.node(nid, label=f"<<B>{u_repr}</B>>", shape='doubleoctagon', 
                             style='filled', fillcolor=fill_c, color=color_c, margin='0.05')
            else:
                f_c, c_c = get_node_style(u_repr)
                lbl = f'<<TABLE BORDER="0" CELLBORDER="0" CELLSPACING="0"><TR><TD BORDER="1" STYLE="ROUNDED" BGCOLOR="{f_c}" COLOR="{c_c}" CELLPADDING="1" PORT="m"><FONT POINT-SIZE="8"><B>{format_tags(u_repr)}</B></FONT></TD></TR></TABLE>>'
                main_dot.node(nid, label=lbl, shape='none', xlabel=get_xlabel(u_repr))
            drawn_main_nodes.add(u_repr)

        for (qa_info, t_sigma), next_qe in pruned_transitions.items():
            curr_qe, o_sigma = qa_info
            u_repr = node_to_scc_id.get(curr_qe, curr_qe)
            v_repr = node_to_scc_id.get(next_qe, next_qe) if next_qe != 'AX' else 'AX'
            if u_repr != v_repr:
                qa_id = get_id((u_repr, o_sigma))
                if qa_id not in drawn_main_nodes:
                    main_dot.node(qa_id, label='', shape='circle', width='0.03', fillcolor='white', style='filled')
                    drawn_main_nodes.add(qa_id)
                src = get_id(u_repr) + (":m" if not isinstance(u_repr, str) else "")
                main_dot.edge(src, qa_id, label=f"<<FONT POINT-SIZE='7'>{o_sigma}</FONT>>")
                if v_repr == 'AX':
                    if not ax_needed:
                        main_dot.node('AX_REAL', label='<<B>AX</B>>', shape='rectangle', style='filled,rounded', 
                                     fillcolor='#FFF1F2', color='#9F1239', fontsize='8')
                        ax_needed = True
                    main_dot.edge(qa_id, 'AX_REAL', label=f"<<FONT POINT-SIZE='7'>{t_sigma}</FONT>>", style='dashed', color='#2563EB')
                else:
                    dst = get_id(v_repr) + (":m" if not isinstance(v_repr, str) else "")
                    main_dot.edge(qa_id, dst, label=f"<<FONT POINT-SIZE='7'>{t_sigma}</FONT>>", style='dashed', color='#2563EB')

        main_dot.render(f"{filename_prefix}_main", cleanup=True)

        # --- 4. 绘制 SCC 子图 (曲线、紧凑布局) ---
        for sid, scc_nodes in scc_contents.items():
            sub_dot = graphviz.Digraph(comment=sid, engine='neato', strict=True)
            # K 越大吸引力越强，外部节点越靠拢
            # overlap=scale 允许在必要时轻微推开节点以看清文字
            sub_dot.attr(overlap='scale', splines='curved', fontname='serif', 
                         sep='+5', esep='+3', K='0.6')
            
            node_set = set(scc_nodes)
            sub_drawn_nodes = set()

            def draw_sub_node(n, is_external=False):
                if n in sub_drawn_nodes: return
                nid = get_id(n)
                if n == 'AX':
                    sub_dot.node(nid, label='<<B>AX</B>>', shape='rectangle', style='filled,rounded', 
                                 fillcolor='#FFF1F2', color='#9F1239', fontsize='7')
                else:
                    f_c, c_c = get_node_style(n, is_external)
                    lbl = f'<<TABLE BORDER="0" CELLBORDER="0" CELLSPACING="0"><TR><TD BORDER="1" STYLE="ROUNDED" BGCOLOR="{f_c}" COLOR="{c_c}" CELLPADDING="1" PORT="m"><FONT POINT-SIZE="7"><B>{format_tags(n)}</B></FONT></TD></TR></TABLE>>'
                    sub_dot.node(nid, label=lbl, shape='none', xlabel=get_xlabel(n))
                sub_drawn_nodes.add(n)

            for (qa_info, t_sigma), next_qe in pruned_transitions.items():
                curr_qe, o_sigma = qa_info
                is_internal = curr_qe in node_set and next_qe in node_set
                is_entry = curr_qe not in node_set and next_qe in node_set
                is_exit = curr_qe in node_set and next_qe not in node_set
                
                if is_internal or is_entry or is_exit:
                    draw_sub_node(curr_qe, (not curr_qe in node_set))
                    draw_sub_node(next_qe, (not next_qe in node_set and next_qe != 'AX'))
                    
                    qa_sub_id = get_id((curr_qe, o_sigma, sid))
                    sub_dot.node(qa_sub_id, label='', shape='circle', width='0.02', fillcolor='white', style='filled')
                    
                    edge_color = '#2563EB' if is_internal else '#999999'
                    # len=0.6 保证内部箭头不缩成一点，len=0.8 限制外部节点距离
                    edge_len = '0.6' if is_internal else '0.8'
                    
                    sub_dot.edge(get_id(curr_qe)+":m", qa_sub_id, label=f"<<FONT POINT-SIZE='6'>{o_sigma}</FONT>>", 
                                 color=edge_color, len=edge_len)
                    sub_dot.edge(qa_sub_id, get_id(next_qe)+(":m" if next_qe != 'AX' else ""), 
                                 label=f"<<FONT POINT-SIZE='6'>{t_sigma}</FONT>>", 
                                 style='dashed', color=edge_color, len=edge_len)

            for fmt in ['svg', 'pdf']:
                sub_dot.format = fmt
                sub_dot.render(f"{filename_prefix}_{sid}", cleanup=True)
        
        return main_dot