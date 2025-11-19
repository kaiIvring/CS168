"""
Your awesome Distance Vector router for CS 168

Based on skeleton code by:
  MurphyMc, zhangwen0411, lab352
"""

import sim.api as api
from cs168.dv import (
    RoutePacket,
    Table,
    TableEntry,
    DVRouterBase,
    Ports,
    FOREVER,
    INFINITY,
)


class DVRouter(DVRouterBase):

    # A route should time out after this interval
    ROUTE_TTL = 15

    # -----------------------------------------------
    # At most one of these should ever be on at once
    SPLIT_HORIZON = False
    POISON_REVERSE = True
    # -----------------------------------------------

    # Determines if you send poison for expired routes
    POISON_EXPIRED = False

    # Determines if you send updates when a link comes up
    SEND_ON_LINK_UP = False

    # Determines if you send poison when a link goes down
    POISON_ON_LINK_DOWN = False

    def __init__(self):
        """
        Called when the instance is initialized.
        DO NOT remove any existing code from this method.
        However, feel free to add to it for memory purposes in the final stage!
        """
        assert not (
            self.SPLIT_HORIZON and self.POISON_REVERSE
        ), "Split horizon and poison reverse can't both be on"

        self.start_timer()  # Starts signaling the timer at correct rate.

        # Contains all current ports and their latencies.
        # See the write-up for documentation.
        self.ports = Ports()

        # This is the table that contains all current routes
        self.table = Table()
        self.table.owner = self

        ##### Begin Stage 10A #####
        # record routes history
        self.history = {}  # key: (port, dst), value: last_sent_latency

        ##### End Stage 10A #####

    def add_static_route(self, host, port):
        """
        Adds a static route to this router's table.

        Called automatically by the framework whenever a host is connected
        to this router.

        :param host: the host.
        :param port: the port that the host is attached to.
        :returns: nothing.
        """
        # `port` should have been added to `peer_tables` by `handle_link_up`
        # when the link came up.
        assert port in self.ports.get_all_ports(), "Link should be up, but is not."

        ##### Begin Stage 1 #####
        self.table[host] = TableEntry(
            dst = host,
            port = port,
            latency = self.ports.get_latency(port),
            expire_time = FOREVER
        )
        ##### End Stage 1 #####

    def handle_data_packet(self, packet, in_port):
        """
        Called when a data packet arrives at this router.

        You may want to forward the packet, drop the packet, etc. here.

        :param packet: the packet that arrived.
        :param in_port: the port from which the packet arrived.
        :return: nothing.
        """
        ##### Begin Stage 2 #####
        dst = packet.dst

        # if the destination does not exsit, drop
        if dst not in self.table:
            return
        
        entry = self.table[dst]
        # if next hop port is invalid, drop
        if entry.port is None:
            return

        # avoid forwarding to the in_port
        if entry.port == in_port:
            return

        # if the latency is greater than or equal to INFINITY, drop
        if entry.latency >= INFINITY:
            return
        
        # normal forward
        self.send(packet, port = entry.port)
        
        
        ##### End Stage 2 #####

    def send_routes(self, force=False, single_port=None):
        """
        Send route advertisements for all routes in the table.

        :param force: if True, advertises ALL routes in the table;
                      otherwise, advertises only those routes that have
                      changed since the last advertisement.
               single_port: if not None, sends updates only to that port; to
                            be used in conjunction with handle_link_up.
        :return: nothing.
        """
        
        ##### Begin Stages 3, 6, 7, 8, 10 #####
        ports = [single_port] if single_port is not None else self.ports.get_all_ports()

        for port in ports:
            for dst, entry in self.table.items():

                # round down latency to INFINITY
                advertised_latency = entry.latency
                if advertised_latency >= INFINITY:
                    advertised_latency = INFINITY

                # only one of "pr" and "sh" can be true

                # Split Horizon
                if self.SPLIT_HORIZON and entry.port == port:
                    continue

                # Poison Reverse
                if self.POISON_REVERSE and entry.port == port:
                    advertised_latency = INFINITY

                # force = False -> check history
                if not force:
                    # check latency
                    last = self.history.get((port, dst))
                    if last == advertised_latency:
                        continue
                
                self.send_route(port, dst, advertised_latency)

                # update route history
                self.history[(port, dst)] = advertised_latency

        ##### End Stages 3, 6, 7, 8, 10 #####

    def expire_routes(self):
        """
        Clears out expired routes from table.
        accordingly.
        """
        
        ##### Begin Stages 5, 9 #####
        expired = [dst for dst, entry in self.table.items() \
                   if entry.expire_time < api.current_time() ]

        for dst in expired:
            entry = self.table[dst]

            # poison expired routes if enabled
            if self.POISON_EXPIRED:
                self.table[dst] = TableEntry(
                    dst = dst,
                    port = entry.port,
                    latency = INFINITY,
                    expire_time = api.current_time() + self.ROUTE_TTL
                )
                self.log(f"Route to {dst} expired -> POISONED", level = "debug")
            # normal behavior - delete expired routes
            else:
                self.table.pop(dst)
                self.log(f"Route to {dst} expired -> DELETED", level = "debug")

        ##### End Stages 5, 9 #####

    def handle_route_advertisement(self, route_dst, route_latency, port):
        """
        Called when the router receives a route advertisement from a neighbor.

        :param route_dst: the destination of the advertised route.
        :param route_latency: latency from the neighbor to the destination.
        :param port: the port that the advertisement arrived on.
        :return: nothing.
        """
        
        ##### Begin Stages 4, 10 #####
        new_cost = self.ports.get_latency(port) + route_latency
        expire = api.current_time() + self.ROUTE_TTL

        # round down latency to INFINITY
        if route_latency >= INFINITY or new_cost >= INFINITY:
            new_cost = INFINITY

        # new destination, add to the table
        if route_dst not in self.table:
            self.table[route_dst] = TableEntry(
                dst = route_dst,
                port = port,
                latency = new_cost,
                expire_time = expire
            )
            self.send_routes(force=False)
            return
        
        entry = self.table[route_dst]

        # advertisement from current next-hop
        if entry.port == port:
            self.table[route_dst] = TableEntry(
                dst = route_dst,
                port = port,
                latency = new_cost,
                expire_time = expire
            ) 
            self.send_routes(force=False)
            return

        # new path is better
        if new_cost < entry.latency:
            self.table[route_dst] = TableEntry(
                dst = route_dst,
                port = port,
                latency = new_cost,
                expire_time = expire
            ) 
            self.send_routes(force=False)
            return

        ##### End Stages 4, 10 #####

    def handle_link_up(self, port, latency):
        """
        Called by the framework when a link attached to this router goes up.

        :param port: the port that the link is attached to.
        :param latency: the link latency.
        :returns: nothing.
        """
        self.ports.add_port(port, latency)

        ##### Begin Stage 10B #####
        if self.SEND_ON_LINK_UP:
            self.send_routes(single_port = port)

        ##### End Stage 10B #####

    def handle_link_down(self, port):
        """
        Called by the framework when a link attached to this router goes down.

        :param port: the port number used by the link.
        :returns: nothing.
        """
        self.ports.remove_port(port)

        ##### Begin Stage 10B #####
        # replace all routes using the port with poison
        if self.POISON_ON_LINK_DOWN:
            for dst, entry in self.table.items():
                if entry.port == port:
                    self.table[dst] = TableEntry(
                        dst = dst,
                        port = port,
                        latency = INFINITY,
                        expire_time = api.current_time() + self.ROUTE_TTL
                    )
            # poison all neighbors
            self.send_routes()
        # otherwise, delete all routes using the port
        else:
            link_down = [dst for dst, entry in self.table.items() \
                            if entry.port == port ]
            for dst in link_down:
                self.table.pop(dst)
                self.log(f"Route to {dst} expired -> DELETED", level = "debug")

        ##### End Stage 10B #####

    # Feel free to add any helper methods!