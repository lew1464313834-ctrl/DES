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
        
        def check_is_vic(tags):
            tag_to_state = {v: k for k, v in lable_ACAG_map.items()}
            return any(len(tag_to_state.get(t, [])) >= 2 and 
                    tag_to_state[t][1].issubset(secret_states) and 
                    len(tag_to_state[t][1]) > 0 for t in tags)

        # 1. 构图
        for (qa_info, t_sigma), next_qe_tags in pruned_transitions.items():
            u_qe = qa_info[0]
            G_analysis.add_node(u_qe, kind='Qe')
            G_analysis.add_node(qa_info, kind='Qa')
            G_analysis.add_node(next_qe_tags, kind='Qe')
            G_analysis.add_edge(u_qe, qa_info, role='env', label=str(qa_info[1]))
            G_analysis.add_edge(qa_info, next_qe_tags, role='atk', label=str(t_sigma))

        # 2. 识别 SCC (节点数 > 1 或有自环)
        sccs = [set(scc) for scc in nx.strongly_connected_components(G_analysis) 
                if len(scc) > 1 or G_analysis.has_edge(list(scc)[0], list(scc)[0])]

        # 颜色配置: Alpha (洋红), Beta (橙), Sink (灰), Complex (绿)
        COLORS = {'alpha': "#DC26DC", 'beta': '#D97706', 'sink': "#6B0513", 'complex': '#16A34A'}
        node_style_map, edge_style_map, scc_log = {}, {}, {}

        def classify_scc_swapped(nodes):
            exit_edges = [(u, v) for u, v in G_analysis.edges(nodes) if v not in nodes]
            exit_nodes = set(v for _, v in exit_edges)
            
            # --- 判定 1: Sink SCC ---
            if not exit_edges:
                return 'sink'
            
            # --- 判定 2: 结构约束检查 ---
            for q_a in [n for n in nodes if G_analysis.nodes[n].get('kind') == 'Qa']:
                successors_in_phi = [v for v in G_analysis.successors(q_a) if v in nodes]
                if len(successors_in_phi) != 1:
                    return 'complex'

            # --- 判定 3: 类型识别 (逻辑已对调) ---
            
            # 对调后的 alpha-SCC: 所有出口节点都是 attack AO-states (Qa)
            is_alpha_exit = all(G_analysis.nodes[v].get('kind') == 'Qa' for v in exit_nodes)
            
            # 对调后的 beta-SCC: 所有出口节点都是 environment AO-states (Qe)
            is_beta_exit = all(G_analysis.nodes[v].get('kind') == 'Qe' for v in exit_nodes)

            if is_alpha_exit:
                return 'alpha'
            if is_beta_exit:
                return 'beta'

            return 'complex'

        # 处理 SCC 并染色
        for i, scc_nodes in enumerate(sccs):
            s_type = classify_scc_swapped(scc_nodes)
            color = COLORS[s_type]
            
            scc_log[f"SCC_{i}"] = {
                "type": s_type,
                "node_count": len(scc_nodes),
                "exit_node_types": list(set(G_analysis.nodes[v]['kind'] for u, v in G_analysis.edges(scc_nodes) if v not in scc_nodes))
            }
            
            for n in scc_nodes:
                node_style_map[n] = color
            for u, v in G_analysis.edges(scc_nodes):
                if v in scc_nodes:
                    edge_style_map[(u, v)] = color

        # 3. 绘图
        dot = graphviz.Digraph(comment='Swapped SCC Definition Graph', format='svg')
        dot.attr(rankdir='TB')

        # 图例描述同步更新
        legend_content = f'''<
        <TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0" CELLPADDING="4">
        <TR><TD COLSPAN="2" BORDER="0"><B>SCC Classification</B></TD></TR>
        <TR><TD WIDTH="25" BGCOLOR="{COLORS['alpha']}"></TD><TD ALIGN="LEFT">Alpha-SCC </TD></TR>
        <TR><TD WIDTH="25" BGCOLOR="{COLORS['beta']}"></TD><TD ALIGN="LEFT">Beta-SCC </TD></TR>
        <TR><TD WIDTH="25" BGCOLOR="{COLORS['sink']}"></TD><TD ALIGN="LEFT">Sink-SCC </TD></TR>
        <TR><TD WIDTH="25" BGCOLOR="{COLORS['complex']}"></TD><TD ALIGN="LEFT">Complex-SCC </TD></TR>
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
                        dot.node(nid, label="{" + ",".join(sorted(map(str, node_obj))) + "}",
                                xlabel=str(qe_map.get(node_obj, "")), shape='rectangle', style='filled, rounded',
                                fillcolor='#DCFCE7' if is_vic else '#F8F9FA', color=b_color, 
                                penwidth='2.5' if b_color in [COLORS['alpha'], COLORS['beta']] else '1.0')
                    else:
                        dot.node(nid, label='', shape='circle', width='0.15', style='filled',
                                fillcolor='black' if b_color == '#475569' else b_color, color=b_color)
                    drawn_nodes.add(nid)

            # 边去重绘制
            edge_configs = [(u_qe, qa_info, u_id, qa_id, qa_info[1], 'env'),
                            (qa_info, next_qe_tags, qa_id, v_id, t_sigma, 'atk')]
            for s_obj, d_obj, sid, did, label, role in edge_configs:
                edge_key = (sid, did, str(label))
                if edge_key not in drawn_edges:
                    e_c = edge_style_map.get((s_obj, d_obj), '#1E293B' if role=='env' else '#2563EB')
                    dot.edge(sid, did, label=f" {label} ", color=e_c, fontcolor=e_c, 
                            style='solid' if role=='env' else 'dashed',
                            penwidth='1.8' if e_c in [COLORS['alpha'], COLORS['beta']] else '1.0')
                    drawn_edges.add(edge_key)

        dot.render(filename, cleanup=True)
        return dot, scc_log