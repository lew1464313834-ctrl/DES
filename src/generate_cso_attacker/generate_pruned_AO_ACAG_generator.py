class PrunedAOACAGSystemCreater:
    @staticmethod
    def generate_pruned_AO_ACAG_transition(ao_transitions, q0_tags):
        """
         Pruning AO-ACAG 算法
        """
        # 1. 初始化 YP = YQ
        pruned_trans = ao_transitions.copy()

        # 2. 删除所有攻击暴露的 AO-states (即指向 AX 的转移)
        # 在我们的结构中，t_sigma 转移到 AX 的边要被切断
        keys_to_delete = [k for k, v in pruned_trans.items() if v == 'AX']
        for k in keys_to_delete:
            del pruned_trans[k]

        # 3. 递归删除无输出的攻击 AO-状态 qa
        while True:
            changed = False
            
            # 获取当前图中所有的 Qa 节点 (即转移的 key[0])
            # 我们的 key 格式是 ( (qe_tags, o_sigma), t_sigma )
            # 所以 Qa 是 k[0]
            all_qas = {k[0] for k in pruned_trans.keys()}
            
            # 统计哪些 Qa 还有合法的出边 (指向 Qe')
            qa_with_outputs = {k[0] for k, v in pruned_trans.items() if v != 'AX'}
            
            # 找出死掉的 Qa (没有任何 t_sigma 能通往合法的 Qe')
            dead_qas = all_qas - qa_with_outputs

            if not dead_qas:
                break

            for q_a in dead_qas:
                # 找到指向该 dead_qa 的所有边
                # 逻辑：删除任何导致攻击者进入“无解局面”的路径
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
                                filename):
        """
        绘制 Pruned AO-ACAG 图：
        1. 自动过滤掉 AX 相关逻辑（剪枝后理论上不存在）。
        2. 只要节点中包含能发现秘密的状态，背景即标为绿色。
        """
        import graphviz
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
                # 状态元组结构: (xi_S, xi_A, z, x) -> xi_A 是第二个元素
                if orig_state and len(orig_state) >= 2:
                    xi_A = orig_state[1]
                    if len(xi_A) > 0 and xi_A.issubset(secret_states):
                        return True
            return False

        visited_nodes = set()

        # --- 1. 初始状态入口 ---
        dot.node('start_node', label='', shape='none', width='0', height='0')
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
                    # 标绿判定
                    is_victory = check_is_secret(node_tags)
                    
                    fill_c = '#DCFCE7' if is_victory else '#F8F9FA'  # 鲜亮的绿 vs 浅灰白
                    color_c = '#166534' if is_victory else '#475569' # 深绿边 vs 灰蓝边
                    pen_w = '2.0' if is_victory else '1.0'           # 绿框加粗
                    
                    label_text = f'<<B>{format_tags(node_tags)}</B>>'
                    dot.node(node_id, label=label_text, shape='rectangle', 
                            style='filled, rounded', fillcolor=fill_c, color=color_c, 
                            penwidth=pen_w, margin='0.1,0.05')
                    visited_nodes.add(node_id)

            # B. 绘制攻击决策点 Qa (小黑圆点)
            if qa_id not in visited_nodes:
                dot.node(qa_id, label='', shape='circle', width='0.1', height='0.1', 
                        fixedsize='true', fillcolor='#0F172A', style='filled', color='none')
                visited_nodes.add(qa_id)

            # C. 绘制边
            # Qe --(观测)--> Qa
            dot.edge(qe_id, qa_id, label=f" {o_sigma} ", 
                    fontname='serif', fontsize='10', color='#1E293B')

            # Qa --(篡改决策)--> Next Qe
            dot.edge(qa_id, next_id, label=f" {t_sigma} ", 
                    fontname='serif:bold', fontsize='10', 
                    style='dashed', color='#2563EB', fontcolor='#2563EB', arrowsize='0.7')

        # --- 3. 渲染 ---
        try:
            dot.render(filename, cleanup=True)
            print(f"Success: Pruned AO-ACAG graph saved to {filename}.svg")
        except Exception as e:
            print(f"Error rendering graph: {e}")
            
        return dot