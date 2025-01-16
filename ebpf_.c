#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <linux/in.h>


// Estructura para la clave de un flujo
struct flow_key_t {
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u8 protocol;
    u64 score0;
    u64 score1;
};
// Estructura para las métricas del flujo
struct flow_metrics_t {
    u64 pkt_count;  // Número de paquetes
    u64 byte_count; // Tamaño total en bytes
    u64 ts_first;   // Timestamp del primer paquete
    u64 ts_last;    // Timestamp del último paquete
};
// Mapa para los flujos
BPF_HASH(flows, struct flow_key_t, struct flow_metrics_t);

// Mapa para recibir datos desde el espacio de usuario
BPF_HASH(user_data_map, u32, u64);
BPF_HASH(user_ip_map, u32, __be32);
BPF_HASH(user_options, u32, u64);

#define MAX_LOOP 1

int capture_http_https(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (struct iphdr *)(data + sizeof(struct ethhdr));
    if ((void *)ip + sizeof(struct iphdr) > data_end)
        return XDP_PASS;

////////////////////////////////

    struct flow_key_t key = {};
        key.src_ip = ip->saddr;
        key.dst_ip = ip->daddr;

        u32 pkt_len = data_end - data; // Longitud del paquete

        // Procesar TCP
        if (ip->protocol == IPPROTO_TCP) {
                            bpf_trace_printk("FLOWS EBPF\n");
            struct tcphdr *tcp = (struct tcphdr *)((void *)ip + sizeof(struct iphdr));
            if ((void *)tcp + sizeof(struct tcphdr) > data_end)
                return XDP_PASS;

            key.src_port = tcp->source;
            key.dst_port = tcp->dest;
            key.protocol = IPPROTO_TCP;
            key.score0 = 0;
            key.score1 = 0;
        }
        // Procesar UDP
        else if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = (struct udphdr *)((void *)ip + sizeof(struct iphdr));
            if ((void *)udp + sizeof(struct udphdr) > data_end)
                return XDP_PASS;

            key.src_port = udp->source;
            key.dst_port = udp->dest;
            key.protocol = IPPROTO_UDP;
            key.score0 = 0;
            key.score1 = 0;
        } else {
            return XDP_PASS; // Ignorar otros protocolos
        }

////////////////////////////////

    u32 key_ip = 0;
    __be32 *target_network = user_ip_map.lookup(&key_ip);
    if(target_network!=0){
        bpf_trace_printk("ENTRA %x == %x",*target_network,ip->daddr);
        for(u32 i=0;i<1;i++){
            key_ip = i;
            target_network = user_ip_map.lookup(&key_ip);
            if (target_network==0) {
                bpf_trace_printk("90 Valor igual a 0  90\n");
                return XDP_PASS;
            }
            if (ip->saddr == *target_network){
/*          if (ip->daddr == *target_network){
                struct tcphdr *tcp = (struct tcphdr *)((void *)ip + sizeof(struct iphdr));
                if ((void *)tcp + sizeof(struct tcphdr) <= data_end){
                    bpf_trace_printk("DIRECCI DE MEMORIA CORRECTA");
                    struct data_t data = {};
                    data.src_ip = ip->saddr;
                    data.dst_ip = ip->daddr;
                    data.src_port = tcp->source;
                    data.dst_port = tcp->dest;
                    data.pkt_len = ((unsigned int *)data_end - (unsigned int *)ctx->data);
                    data.ts_nsec = bpf_ktime_get_ns();
                    events.perf_submit(ctx, &data, sizeof(data));
*/        bpf_trace_printk("106\n");

                    return XDP_DROP;
                //}
            }
        }
    }
    
    struct tcphdr *tcp = (struct tcphdr *)((void *)ip + sizeof(struct iphdr));
    if ((void *)tcp + sizeof(struct tcphdr) > data_end)
        return XDP_PASS;

    u32 key_port = 0;    
    u64 *index = user_data_map.lookup(&key_port);
    if(index!=0){
        u64 limit = *index > MAX_LOOP ? *index : MAX_LOOP;
        if(limit==0)return XDP_PASS;
        for(u32 i=0;i<4;i++){
            bpf_trace_printk("Limit: %d\n", i);
            u32 key2 = i;
            u64 *valor = user_data_map.lookup(&key2);
            if (valor==0) {
                bpf_trace_printk("128 Valor igual a 0\n");
                return XDP_PASS;
            }
            if (tcp->source == bpf_htons(*valor)) {
                /*
                struct data_t data = {};
                data.src_ip = ip->saddr;
                data.dst_ip = ip->daddr;
                data.src_port = tcp->source;
                data.dst_port = tcp->dest;
                data.pkt_len = ((unsigned int *)data_end - (unsigned int *)ctx->data);
                data.ts_nsec = bpf_ktime_get_ns();
                events.perf_submit(ctx, &data, sizeof(data));
                */
                        bpf_trace_printk("142\n");

                return XDP_DROP;
            }
        }
        /*
        struct data_t data = {};
        data.src_ip = ip->saddr;
        data.dst_ip = ip->daddr;
        data.src_port = tcp->source;
        data.dst_port = tcp->dest;
        data.pkt_len = ((unsigned int *)data_end - (unsigned int *)ctx->data);
        data.ts_nsec = bpf_ktime_get_ns();
        events.perf_submit(ctx, &data, sizeof(data));
        */
    }


////////////////////////////

    // Actualizar las métricas del flujo
    struct flow_metrics_t *metrics = flows.lookup(&key);
    struct flow_metrics_t new_metrics = {};

    if (metrics) {
        metrics->pkt_count += 1;
        metrics->byte_count += pkt_len;
        new_metrics.ts_last = new_metrics.ts_first;
        new_metrics.byte_count = pkt_len;
        flows.update(&key, &new_metrics);
    }

////////////////////////////
    u64 port80=0;
    if (tcp->source == bpf_htons(80)) port80=1;
    u64 len = ((unsigned int *)data_end - (unsigned int *)ctx->data);
    u64 cport = tcp -> dest;
    u64 input[3] = {len,cport,port80};


    u64 output[2];
    u64 var0[2];

if (input[0] <= 2027.0) {
    if (input[0] <= 149.5) {
        if (input[1] <= 62531.5) {
            if (input[2] <= 0.5) {
                var0[0] = 1000000000;
                var0[1] = 0;
            } else {
                if (input[0] <= 37.0) {
                    if (input[1] <= 50853.0) {
                        var0[0] = 843949044586;
                        var0[1] = 156050955414;
                    } else {
                        if (input[1] <= 56777.5) {
                            var0[0] = 593541202673;
                            var0[1] = 406458797327;
                        } else {
                            var0[0] = 785591766724;
                            var0[1] = 214408233276;
                        }
                    }
                } else {
                    var0[0] = 258620689655;
                    var0[1] = 741379310345;
                }
            }
        } else {
            var0[0] = 238805970149;
            var0[1] = 761194029851;
        }
    } else {
        if (input[0] <= 240.5) {
            if (input[2] <= 0.5) {
                var0[0] = 1000000000;
                var0[1] = 0;
            } else {
                if (input[1] <= 48860.5) {
                    var0[0] = 1000000000;
                    var0[1] = 0;
                } else {
                    var0[0] = 325594563399;
                    var0[1] = 967440543601;
                }
            }
        } else {
            if (input[1] <= 56648.5) {
                if (input[1] <= 48860.5) {
                    var0[0] = 1000000000;
                    var0[1] = 0;
                } else {
                    if (input[0] <= 1099.0) {
                        if (input[0] <= 384.5) {
                            if (input[0] <= 383.5) {
                                var0[0] = 483760683761;
                                var0[1] = 516239316239;
                            } else {
                                var0[0] = 127462340672;
                                var0[1] = 987253765933;
                            }
                        } else {
                            if (input[1] <= 55209.5) {
                                var0[0] = 681118083286;
                                var0[1] = 318881916714;
                            } else {
                                var0[0] = 247011952191;
                                var0[1] = 752988047809;
                            }
                        }
                    } else {
                        if (input[0] <= 1151.5) {
                            var0[0] = 416666666667;
                            var0[1] = 958333333333;
                        } else {
                            if (input[0] <= 1909.5) {
                                var0[0] = 551794871795;
                                var0[1] = 448205128205;
                            } else {
                                var0[0] = 451467268862;
                                var0[1] = 954853273138;
                            }
                        }
                    }
                }
            } else {
                if (input[0] <= 1934.5) {
                    if (input[0] <= 402.5) {
                        if (input[0] <= 383.5) {
                            var0[0] = 880851063830;
                            var0[1] = 119148936170;
                        } else {
                            var0[0] = 172413793103;
                            var0[1] = 827586206897;
                        }
                    } else {
                        if (input[1] <= 57205.5) {
                            if (input[0] <= 961.5) {
                                var0[0] = 878151260504;
                                var0[1] = 121848739496;
                            } else {
                                var0[0] = 236842105263;
                                var0[1] = 763157894737;
                            }
                        } else {
                            var0[0] = 934684684685;
                            var0[1] = 653153153153;
                        }
                    }
                } else {
                    if (input[0] <= 1943.5) {
                        var0[0] = 512820512820;
                        var0[1] = 994871794872;
                    } else {
                        var0[0] = 100000000000;
                        var0[1] = 0;
                    }
                }
            }
        }
    }
} else {
    if (input[1] <= 56929.5) {
        if (input[1] <= 55262.5) {
            if (input[1] <= 49283.0) {
                var0[0] = 980337078652;
                var0[1] = 196629213348;
            } else {
                if (input[0] <= 19375.0) {
                    if (input[0] <= 3037.5) {
                        var0[0] = 829015544041;
                        var0[1] = 170984455959;
                    } else {
                        if (input[1] <= 49944.5) {
                            var0[0] = 531468531469;
                            var0[1] = 468531468531;
                        } else {
                            if (input[1] <= 50370.5) {
                                var0[0] = 949367088608;
                                var0[1] = 506329113924;
                            } else {
                                var0[0] = 641937925814;
                                var0[1] = 358062074186;
                            }
                        }
                    }
                } else {
                    var0[0] = 846780766096;
                    var0[1] = 153219233904;
                }
            }
        } else {
            if (input[1] <= 56438.5) {
                var0[0] = 369127516779;
                var0[1] = 963087248322;
            } else {
                var0[0] = 752475247525;
                var0[1] = 247524752475;
            }
        }
    } else {
        if (input[1] <= 61905.5) {
            var0[0] = 987212276215;
            var0[1] = 127877237851;
        } else {
            if (input[0] <= 68705.0) {
                var0[0] = 881294964029;
                var0[1] = 118705035971;
            } else {
                var0[0] = 198198198198;
                var0[1] = 801801801802;
            }
        }
    }
}



    output[0] = var0[0];
    output[1] = var0[1];

    key.score0 = var0[0];
    key.score1 = var0[1];

    u32 key_opt = 0;
    u64 *opt = user_options.lookup(&key_opt);
    if(opt!=0 && *opt==1){
        if(output[0]<var0[1])
            return XDP_DROP;
    }

    return XDP_PASS;
}

