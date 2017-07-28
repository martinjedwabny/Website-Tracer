#! /usr/bin/env python
import sys
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import operator
from scipy import stats
from outliers import *

TIMEOUT = 1

def obtener_ruta(hostname, verbose):
    ruta = []
    tiempos = []
    for i in range(1, 30):
        pkt = IP(dst=hostname, ttl=i) / ICMP()
        # Mandar paquete y obtener reply
        # Guardar en 'ans' una lista de (send, reply) por cada envio (en este caso solo pkt)
        ans, unans = sr(pkt, verbose=0, timeout=TIMEOUT)

        if not ans:
            # No llego respuesta
            if verbose == False: print "%d hops away: *" % i
            ruta.append("*")
            tiempos.append(-1)
            continue

        # Obtener paquete enviado y respuesta
        send, reply = ans[0]
        if reply is None:
            if verbose == False: print "%d hops away: *" % i
            ruta.append("*")
            tiempos.append(-1)
        else:
            RTT  = (reply.time - send.sent_time) * 1000
            if verbose == False: print "%d hops away: %s in %.4f ms" % (i , reply.src, RTT)
            ruta.append(reply.src)
            tiempos.append(RTT)
            if reply.type == 0:
                # Llegamos al destino (echo reply)
                if verbose == False: print "Done!"
                break
    return ruta, tiempos

def calcular_ruta_comun(rutas_y_tiempos):
    ruta_comun = []
    rutas_a_procesar = rutas_y_tiempos
    for i in range(0, 29):
        hops_en_posicion_i = {}
        # Cuento cuantas veces aparece cada ip en el hop numero i
        for (ruta, tiempos) in rutas_a_procesar:
            if len(ruta) <= i:
                continue
            ip = ruta[i]
            if ip in hops_en_posicion_i:
                hops_en_posicion_i[ip] = hops_en_posicion_i[ip] + 1
            else:
                hops_en_posicion_i[ip] = 1

        if len(hops_en_posicion_i) == 0:
            break

        # Veo cual es la ip que aparece mas veces en el hop numero i
        ip_con_mas_apariciones = max(hops_en_posicion_i.iteritems(), key=operator.itemgetter(1))[0]
        ruta_comun.append(ip_con_mas_apariciones)

        # Filtro todas las rutas que no tenian esa ip en el hop numero i
        nuevas_rutas = []
        for (ruta, tiempos) in rutas_a_procesar:
            if ruta[i] == ip_con_mas_apariciones:
                nuevas_rutas.append((ruta, tiempos))
        rutas_a_procesar = nuevas_rutas

    return ruta_comun, [tiempos for (ruta, tiempos) in rutas_a_procesar]

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print ''
        print "Usage: " + sys.argv[0] + " <IP>"
        exit(1)

    verbose = False
    intentos = 1
    if len(sys.argv) > 2 and sys.argv[2] == '-d':
        verbose = True
        intentos = 50

    ip = sys.argv[1]
    rutas_y_tiempos = []
    for j in range(1,intentos+1):
        if verbose: print "Realizando traceroute %d a IP %s" % (j, ip)
        ruta, tiempos = obtener_ruta(ip, verbose)
        rutas_y_tiempos.append((ruta, tiempos))

    if verbose:

        print ""

        ruta_comun, tiempos = calcular_ruta_comun(rutas_y_tiempos)
        print "\tRuta establecida: %s\n" % ruta_comun
        print "\tTiempos obtenidos para la ruta:\n%s" % tiempos
        # Para cada hop, saco los outliers de los tiempos
        tiempos_sin_outliers = []
        for hop in xrange(len(tiempos[0])):
            if ruta_comun[hop] == "*":
                tiempos_sin_outliers.append(-1)
                continue
            # Guardo en una lista todos los tiempos de un hop
            tiempos_hop = []
            for tiempo in tiempos:
                tiempos_hop.append(tiempo[hop])
            quitarOutliers(tiempos_hop)
            tiempos_sin_outliers.append(calcularMedia(tiempos_hop))

        print ""
        print "\tTiempos sin outliers y promediados: %s\n" % tiempos_sin_outliers

        # Busco outliers como candidatos a salto intercontinentales, primero calculo los delta_rtt
        delta_rtt_hops = []
        delta_rtt_tiempos = []
        delta = 0
        rtt_anterior = tiempos_sin_outliers[0]
        ip_anterior = ruta_comun[0]
        for i in range(1, len(ruta_comun)):
            rtt_actual = tiempos_sin_outliers[i]
            ip_actual = ruta_comun[i]
            if rtt_actual != -1 and rtt_anterior != -1:
                delta = rtt_actual - rtt_anterior
                delta_rtt_ip = str(ip_anterior) + "-" + str(ip_actual)
                delta_rtt_hops.append(delta_rtt_ip)
                delta_rtt_tiempos.append(delta)
                if delta < 0:
                    print "\tWarning: salto negativo entre los hops %d y %d" % (i-1, i)
            rtt_anterior = rtt_actual
            ip_anterior = ip_actual
        delta_rtt_tiempos_aux = list(delta_rtt_tiempos)
        # Me quedo con los outliers
        outliers = quitarOutliers(delta_rtt_tiempos_aux)
        for hop in xrange(len(outliers)):
            for i in xrange(len(delta_rtt_tiempos)):
                if outliers[hop] == delta_rtt_tiempos[i]:
                    print "\nPosible salto continental entre las IPs: %s" % (delta_rtt_hops[i])

        print "\nGeolocalizacion de las IPs:"
        for ip in ruta_comun:
            print ""
            if ip != "*":
                print "IP: %s" % ip
                os.system("curl ipinfo.io/%s" % ip)
            else:
                print "IP: *"
