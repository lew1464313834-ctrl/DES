import graphviz
import networkx as nx

class AttackerGenerator:

    @staticmethod
    def draw_purned_AO_ACAG_graph_marked_SCC(pruned_transitions, 
                                    lable_ACAG_map,
                                    secret_states,
                                    qe_map, 
                                    filename):

        G_analysis = nx.DiGraph()
        victory_nodes = set()
        
        def check_is_vic(tags):
            tag_to_state = {v: k for k, v in lable_ACAG_map.items()}
            return any(len(tag_to_state.get(t, [])) >= 2 and 
                       tag_to_state[t][1].issubset(secret_states) and 
                       len(tag_to_state[t][1]) > 0 for t in tags)

        # 1. 建图
        for (qa_info, t_sigma), next_qe_tags in pruned_transitions.items():
            u_qe = qa_info[0]
            G_analysis.add_node(u_qe, kind='Qe')
            G_analysis.add_node(qa_info, kind='Qa')
            G_analysis.add_node(next_qe_tags, kind='Qe')
            G_analysis.add_edge(u_qe, qa_info, role='env', label=str(qa_info[1]))
            G_analysis.add_edge(qa_info, next_qe_tags, role='atk', label=str(t_sigma))
            if check_is_vic(u_qe): victory_nodes.add(u_qe)
            if check_is_vic(next_qe_tags): victory_nodes.add(next_qe_tags)

        can_reach_secret = set()
        for vic in victory_nodes:
            can_reach_secret.update(nx.ancestors(G_analysis, vic))
            can_reach_secret.add(vic)

        # 2. 环识别
        all_loop_nodes = []
        try:
            for scc in nx.strongly_connected_components(G_analysis):
                if len(scc) >= 2 or G_analysis.has_edge(list(scc)[0], list(scc)[0]):
                    sub = G_analysis.subgraph(scc)
                    for cycle in nx.simple_cycles(sub):
                        all_loop_nodes.append(set(cycle))
                    all_loop_nodes.append(set(scc))
        except:
            all_loop_nodes = [set(scc) for scc in nx.strongly_connected_components(G_analysis) if len(scc) > 0]

        COLORS = {'alpha': "#DC26DC", 'beta': '#D97706', 'sink': '#94A3B8', 'complex': '#16A34A'}
        node_style_map, edge_style_map, scc_log = {}, {}, {}

        def classify_loop(nodes, idx):
            nodes = set(nodes)
            exit_edges = [(u, v) for u, v in G_analysis.edges(nodes) if v not in nodes]
            
            # 预计算属性
            leads_secret = any(v in can_reach_secret for _, v in exit_edges)
            
            # --- 优先级 1: Alpha/Beta (结构敏感) ---
            if exit_edges and leads_secret:
                is_alpha = all(G_analysis.nodes[u].get('kind') == 'Qe' and G_analysis.nodes[v].get('kind') == 'Qa' for u, v in exit_edges)
                if is_alpha: return 'alpha'
                
                is_beta = all(G_analysis.nodes[u].get('kind') == 'Qa' and G_analysis.nodes[v].get('kind') == 'Qe' for u, v in exit_edges)
                if is_beta: return 'beta'

            # --- 优先级 2: Sink (无出口或死路) ---
            if not exit_edges or not leads_secret:
                return 'sink'

            # --- 优先级 3: Complex ---
            scc_log[f"Loop_{idx}"] = {"exits": len(exit_edges), "leads_secret": leads_secret}
            return 'complex'

        # 排序与染色：按大小从小到大，且 Alpha/Beta 拥有最高染色优先级
        all_loop_nodes.sort(key=len)
        for i, nodes in enumerate(all_loop_nodes):
            l_type = classify_loop(nodes, i)
            color = COLORS[l_type]
            for n in nodes:
                # 只有当新颜色是 Alpha/Beta，或者节点还没颜色时才覆盖
                if n not in node_style_map or color in [COLORS['alpha'], COLORS['beta']]:
                    node_style_map[n] = color
            for u, v in G_analysis.edges(nodes):
                if v in nodes:
                    if (u, v) not in edge_style_map or color in [COLORS['alpha'], COLORS['beta']]:
                        edge_style_map[(u, v)] = color

        # --- 3. 绘图 (去重过滤) ---
        dot = graphviz.Digraph(comment='SCC Prioritized Graph', format='svg')
        dot.attr(rankdir='TB')

        # 图例更新顺序
        legend_content = f'''<
        <TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0" CELLPADDING="6">
          <TR><TD COLSPAN="2" BORDER="0"><B>SCC Classification</B></TD></TR>
          <TR><TD WIDTH="30" BGCOLOR="{COLORS['alpha']}"></TD><TD ALIGN="LEFT">1. Alpha-SCC </TD></TR>
          <TR><TD WIDTH="30" BGCOLOR="{COLORS['beta']}"></TD><TD ALIGN="LEFT">2. Beta-SCC </TD></TR>
          <TR><TD WIDTH="30" BGCOLOR="{COLORS['sink']}"></TD><TD ALIGN="LEFT">3. Sink-SCC</TD></TR>
          <TR><TD WIDTH="30" BGCOLOR="{COLORS['complex']}"></TD><TD ALIGN="LEFT">4. Complex-SCC</TD></TR>
        </TABLE>>'''
        dot.node('legend', label=legend_content, shape='none')

        def get_safe_id(obj): return f"n_{abs(hash(str(obj)))}"

        drawn_nodes, drawn_edges = set(), set()

        for (qa_info, t_sigma), next_qe_tags in pruned_transitions.items():
            u_qe = qa_info[0]
            u_id, qa_id, v_id = get_safe_id(u_qe), get_safe_id(qa_info), get_safe_id(next_qe_tags)

            # 节点去重绘制
            for node_obj, nid, kind in [(u_qe, u_id, 'Qe'), (next_qe_tags, v_id, 'Qe'), (qa_info, qa_id, 'Qa')]:
                if nid not in drawn_nodes:
                    b_color = node_style_map.get(node_obj, '#475569')
                    if kind == 'Qe':
                        is_vic = check_is_vic(node_obj)
                        dot.node(nid, label="{" + ",".join(sorted(list(map(str, node_obj)))) + "}",
                                 xlabel=str(qe_map.get(node_obj, "")), shape='rectangle', style='filled, rounded',
                                 fillcolor='#DCFCE7' if is_vic else '#F8F9FA', color=b_color, 
                                 penwidth='2.5' if b_color in [COLORS['alpha'], COLORS['beta']] else '1.2')
                    else:
                        dot.node(nid, label='', shape='circle', width='0.15', style='filled',
                                 fillcolor='black' if b_color == '#475569' else b_color, color=b_color)
                    drawn_nodes.add(nid)

            # 边去重绘制
            edge_configs = [
                (u_id, qa_id, str(qa_info[1]), 'env', u_qe, qa_info),
                (qa_id, v_id, str(t_sigma), 'atk', qa_info, next_qe_tags)
            ]

            for sid, did, lab, role, s_obj, d_obj in edge_configs:
                edge_key = (sid, did, lab, role)
                if edge_key not in drawn_edges:
                    e_c = edge_style_map.get((s_obj, d_obj), '#1E293B' if role=='env' else '#2563EB')
                    dot.edge(sid, did, label=f" {lab} ", color=e_c, fontcolor=e_c, 
                             style='solid' if role=='env' else 'dashed',
                             penwidth='1.8' if e_c in [COLORS['alpha'], COLORS['beta']] else '1.0')
                    drawn_edges.add(edge_key)

        dot.render(filename, cleanup=True)
        return dot, scc_log