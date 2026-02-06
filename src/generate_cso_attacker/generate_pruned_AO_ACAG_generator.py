import graphviz

class PrunedAOACAGSystemCreater:
    @staticmethod
    def generate_pruned_AO_ACAG_transition(ao_transitions, q0_tags):
        """
         Pruning AO-ACAG 算法
        """
        # 1. 初始化 YP = YQ
        pruned_trans = ao_transitions.copy()

        # 2. 删除所有攻击暴露的 AO-states (即指向 AX 的转移)
        keys_to_delete = [k for k, v in pruned_trans.items() if v == 'AX']
        for k in keys_to_delete:
            del pruned_trans[k]

        # 3. 递归删除无输出的攻击 AO-状态 qa
        while True:
            changed = False
            all_qas = {k[0] for k in pruned_trans.keys()}
            
            # 统计哪些 Qa 还有合法的出边 (指向 Qe')
            qa_with_outputs = {k[0] for k, v in pruned_trans.items() if v != 'AX'}
            
            # 找出死掉的 Qa (没有任何 t_sigma 能通往合法的 Qe')
            dead_qas = all_qas - qa_with_outputs

            if not dead_qas:
                break

            for q_a in dead_qas:
                target_edges = [k for k, v in pruned_trans.items() if v == q_a]
                if target_edges:
                    for k in target_edges:
                        del pruned_trans[k]
                    changed = True
            
            if not changed:
                break
        return pruned_trans, q0_tags
    
    @staticmethod
    def draw_pruned_AO_ACAG_graph(pruned_transitions, 
                                q0_tags,
                                lable_ACAG_map,
                                secret_states,
                                qe_map, # 新增参数：传入 draw_AO_ACAG_graph 返回的编号映射
                                filename):
        """
        绘制 Pruned AO-ACAG 图
        """
        dot = graphviz.Digraph(comment='Pruned AO-ACAG System', format='svg')
        
        # 全局风格配置
        dot.attr(
            rankdir='TB',
            nodesep='0.4', 
            ranksep='0.5',
            fontname='serif',
            fontsize='11',
            splines='spline',
            forcelabels='true'
        )

        def get_id(obj):
            return hex(hash(str(obj)) & 0xffffffff)

        def format_tags(tags):
            return "{" + ",".join(tags) + "}"

        # 建立标签到原始状态的逆映射
        tag_to_state = {v: k for k, v in lable_ACAG_map.items()}

        def check_is_secret(tags):
            """判定节点集合是否包含秘密发现状态"""
            for tag in tags:
                orig_state = tag_to_state.get(tag)
                if orig_state and len(orig_state) >= 2:
                    xi_A = orig_state[1]
                    if len(xi_A) > 0 and xi_A.issubset(secret_states):
                        return True
            return False

        visited_nodes = set()
        visited_edges = set()

        # --- 1. 初始状态入口 ---
        dot.node('start_node', label='', shape='none', width='0', height='0')
        # 获取 q0 的编号
        q0_label = qe_map.get(q0_tags, "qe?") 
        dot.edge('start_node', get_id(q0_tags), arrowsize='0.7', penwidth='1.2')

        # --- 2. 遍历剪枝后的转移关系 ---
        for (qa_info, t_sigma), next_qe_tags in pruned_transitions.items():
            curr_qe_tags, o_sigma = qa_info
            
            qe_id = get_id(curr_qe_tags)
            qa_id = get_id(qa_info)
            next_id = get_id(next_qe_tags)

            # A. 绘制环境状态 Qe (矩形)
            for node_tags, node_id in [(curr_qe_tags, qe_id), (next_qe_tags, next_id)]:
                if node_id not in visited_nodes:
                    is_victory = check_is_secret(node_tags)
                    
                    fill_c = '#DCFCE7' if is_victory else '#F8F9FA'
                    color_c = '#166534' if is_victory else '#475569'
                    pen_w = '2.0' if is_victory else '1.0'
                    
                    # 从 qe_map 获取对应的编号
                    qe_label = qe_map.get(node_tags, "")
                    
                    label_text = f'<<B>{format_tags(node_tags)}</B>>'
                    dot.node(node_id, 
                            label=label_text, 
                            xlabel=qe_label, # 在节点外部标注编号
                            shape='rectangle', 
                            style='filled, rounded', 
                            fillcolor=fill_c, 
                            color=color_c, 
                            penwidth=pen_w, 
                            margin='0.1,0.05',
                            fontsize='10')
                    visited_nodes.add(node_id)

            # B. 绘制攻击决策点 Qa
            if qa_id not in visited_nodes:
                dot.node(qa_id, label='', shape='circle', width='0.1', height='0.1', 
                        fixedsize='true', fillcolor='#ffffffff', style='filled', color='#00000000')
                visited_nodes.add(qa_id)

            # C. 绘制边
            edge_key = (qe_id, qa_id)
            if edge_key not in visited_edges:
                dot.edge(qe_id, qa_id, label=f" {o_sigma} ", 
                        fontname='serif', fontsize='10', color='#1E293B')
                visited_edges.add(edge_key)

            # Qa --(篡改决策)--> Next Qe
            dot.edge(qa_id, next_id, label=f" {t_sigma} ", 
                    fontname='serif:bold', fontsize='10', 
                    style='dashed', color='#2563EB', fontcolor='#2563EB', arrowsize='0.7')

        # --- 3. 渲染 ---
        try:
            dot.render(filename, cleanup=True)
            print(f"Success: Pruned AO-ACAG graph saved to {filename}")
        except Exception as e:
            print(f"Error rendering graph: {e}")
            
        return dot