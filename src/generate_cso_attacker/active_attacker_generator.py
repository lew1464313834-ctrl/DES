import graphviz
import networkx as nx
class AttackerGenerator:

    @staticmethod
    def draw_purned_AO_ACAG_with_success_value(pruned_transitions, lable_ACAG_map, secret_states, qe_map, filename):
        """
        绘制带有成功值的 Pruned AO-ACAG 图 (回归原始风格)
        风格：
        1. 节点内部：只显示集合内容 {tags} (原始风格)。
        2. 节点外部 (xlabel)：显示编号 qeX 和 成功值 v=...。
        3. 优化：保留了边去重逻辑，防止连线混乱。
        """

        # --- 1. 计算逻辑 (SCC 与 成功值) ---
        
        # 建立环境节点演化图
        G_env = nx.DiGraph()
        for (qa_info, t_sigma), next_qe_tags in pruned_transitions.items():
            curr_qe_tags, _ = qa_info
            G_env.add_edge(curr_qe_tags, next_qe_tags)

        # 识别 SCC 并缩点
        sccs = list(nx.strongly_connected_components(G_env))
        condensed_G = nx.condensation(G_env)
        reverse_topo_order = list(nx.topological_sort(condensed_G))[::-1]

        success_values = {} 
        tag_to_state = {v: k for k, v in lable_ACAG_map.items()}

        def is_secret_qe(tags):
            for tag in tags:
                orig = tag_to_state.get(tag)
                if orig and len(orig) >= 2 and orig[1].issubset(secret_states) and len(orig[1]) > 0:
                    return True
            return False

        # 计算成功值
        for scc_idx in reverse_topo_order:
            nodes_in_scc = condensed_G.nodes[scc_idx]['members']
            scc_contains_secret = any(is_secret_qe(node) for node in nodes_in_scc)
            
            exits = []
            for node in nodes_in_scc:
                for neighbor in G_env.neighbors(node):
                    if neighbor not in nodes_in_scc:
                        exits.append(success_values[neighbor])

            if scc_contains_secret:
                scc_val = 1.0
            elif not exits:
                scc_val = 0.0
            else:
                m = len(exits)
                scc_val = (max(exits) + sum(exits)) / (m + 1)

            for node in nodes_in_scc:
                success_values[node] = scc_val

        # --- 2. 绘图逻辑 (原始风格 + 外部标签) ---
        dot = graphviz.Digraph(comment='Pruned AO-ACAG Success Value', format='svg')
        
        # 风格配置：增大 nodesep 以给外部标签留出空间
        dot.attr(
            rankdir='TB',
            nodesep='0.7',  # 增大间距，防止 xlabel 遮挡
            ranksep='0.6',
            fontname='serif',
            fontsize='11',
            splines='spline',
            forcelabels='true' # 强制显示 xlabel
        )

        def get_id(obj): return hex(hash(str(obj)) & 0xffffffff)
        
        def format_tags(tags):
            return "{" + ",".join(sorted(list(tags))) + "}"

        visited_nodes = set()
        visited_edges = set() 

        for (qa_info, t_sigma), next_qe_tags in pruned_transitions.items():
            curr_qe_tags, o_sigma = qa_info
            
            curr_id = get_id(curr_qe_tags)
            next_id = get_id(next_qe_tags)
            qa_id = get_id(qa_info)

            # A. 绘制 Qe 节点
            for tags, node_id in [(curr_qe_tags, curr_id), (next_qe_tags, next_id)]:
                if node_id not in visited_nodes:
                    val = success_values.get(tags, 0.0)
                    is_vic = is_secret_qe(tags)
                    
                    # 样式设置 (完全保留原始 style)
                    fill_c = '#DCFCE7' if is_vic else '#F8F9FA'
                    color_c = '#166534' if is_vic else '#475569'
                    pen_w = '2.0' if is_vic else '1.0'
                    
                    # 获取编号和值
                    qe_label = qe_map.get(tags, "qe?")
                    val_str = f"{int(val)}" if val in [0.0, 1.0] else f"{val:.2f}"
                    
                    # 构造外部标签 (xlabel)：上方编号，下方数值
                    # 使用 HTML 格式控制颜色和加粗
                    xlabel_html = f'''<<TABLE BORDER="0" CELLBORDER="0" CELLSPACING="0">
                        <TR><TD><B>{qe_label}</B></TD></TR>
                        <TR><TD><FONT COLOR="#2563EB" POINT-SIZE="14">v={val_str}</FONT></TD></TR>
                    </TABLE>>'''

                    # 节点内部只显示 tags
                    label_text = f'<<B>{format_tags(tags)}</B>>'

                    dot.node(node_id, 
                            label=label_text,       # 内部：集合
                            xlabel=xlabel_html,     # 外部：编号+数值
                            shape='rectangle', 
                            style='filled, rounded', 
                            fillcolor=fill_c, 
                            color=color_c,
                            penwidth=pen_w,
                            margin='0.1,0.05')
                    visited_nodes.add(node_id)

            # B. 绘制 Qa 节点 (小圆圈)
            if qa_id not in visited_nodes:
                dot.node(qa_id, label='', shape='circle', width='0.1', height='0.1', 
                        fixedsize='true', fillcolor='#ffffffff', style='filled', color='#00000000')
                visited_nodes.add(qa_id)

            # C. 绘制连线 (去重)
            
            # 1. Qe -> Qa (环境观测)
            edge_key1 = (curr_id, qa_id, o_sigma)
            if edge_key1 not in visited_edges:
                dot.edge(curr_id, qa_id, label=f" {o_sigma} ", 
                         fontname='serif', fontsize='10', color='#1E293B')
                visited_edges.add(edge_key1)

            # 2. Qa -> Qe (攻击决策)
            edge_key2 = (qa_id, next_id, t_sigma)
            if edge_key2 not in visited_edges:
                dot.edge(qa_id, next_id, label=f" {t_sigma} ", 
                         fontname='serif:bold', fontsize='10', 
                         style='dashed', color='#2563EB', fontcolor='#2563EB', arrowsize='0.7')
                visited_edges.add(edge_key2)
        dot.render(filename, cleanup=True)
        return dot