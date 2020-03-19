package edu.uconn

import java.lang.IllegalArgumentException

class BayesianNetwork <K: Any>(val source: K, val sink:K) {
    val nodes = mutableMapOf<K, Double>()
    val unions = mutableSetOf<K>()
    val edges = mutableMapOf<K, MutableSet<K>>()
    val cumulativeProbabilities = mutableMapOf<K, Double>()
    val reverseEdges = mutableMapOf<K, MutableSet<K>>()

    init {
        addNode(source, 1.0)
        cumulativeProbabilities[source] = 1.0
        addNode(sink,1.0)
    }

    /**
     * Add a node to the network. If the node already exists, this will not update it
     * @param id The id of the node being added
     * @param weight The weight of the node being added
     */
    fun addNode(id: K, weight: Double, union: Boolean = false){
        if(id in nodes.keys)
            return
        this.nodes[id] = weight
        this.edges[id] = mutableSetOf()
        this.reverseEdges[id] = mutableSetOf()
        this.cumulativeProbabilities[id] = 0.0
        if(union)
            this.unions.add(id)
    }

    /**
     * Changes a node from its normal state to a state in which it is constituents are calculated as a union in the model
     *
     * @param id the id of the node being added
     * @throws IllegalArgumentException thrown if [id] does not exist in [nodes]
     */
    fun toggleUnion(id: K){
        if(id !in nodes.keys)
            throw IllegalArgumentException("$id not found in nodes")
        if(id in unions)
            unions.remove(id)
        else
            unions.add(id)
    }

    /**
     * Adds an edge between [from] and [to]. The network is directed, so the edge is one-way.
     * Multi-edges and self edges will be ignored.
     *
     * @param from the id of the starting node
     * @param to the id of the end node
     * @throws IllegalArgumentException thrown if [from] or [to] do not exist in [nodes]
     */
    fun addEdge(from: K, to: K){
        if(from !in nodes.keys)
            throw IllegalArgumentException("$from not found in nodes")
        if(to !in nodes.keys)
            throw IllegalArgumentException("$to not found in nodes")
        if(to == this.source)
            throw IllegalArgumentException("to end of edge cannot be the source")
        if(from == this.sink)
            throw IllegalArgumentException("from end of edge cannot be the sink")
        if(to == from || to in edges[from]!! || to in reverseEdges[from]!!)
            return
        this.edges[from]!!.add(to)
        this.reverseEdges[to]!!.add(from)
        // Calculate cumulative weight of to
        val oldIn = cumulativeProbabilities[to]!!/nodes[to]!!

        if(to in unions){
            if(reverseEdges[to]!!.size <= 1)
                cumulativeProbabilities[to] = cumulativeProbabilities[from]!!
            else
                cumulativeProbabilities[to] = oldIn*cumulativeProbabilities[from]!!
        } else {
            cumulativeProbabilities[to] = oldIn + cumulativeProbabilities[from]!! - oldIn*cumulativeProbabilities[from]!!
//            println("$oldIn + ${nodes[from]} - $oldIn*${nodes[from]}")
        }
//        println("$from->$to $oldIn->${cumulativeProbabilities[to]}")
        cumulativeProbabilities[to] = cumulativeProbabilities[to]!! * nodes[to]!!
        //recursively calculate its neighbors
        for(node in this.edges[to]!!){
            reweigh(oldIn*nodes[to]!!, cumulativeProbabilities[to]!!, node)
        }
//        println("$from $to $cumulativeProbabilities")
    }

    private fun reweigh(old: Double, new: Double, id: K){
//        println("$id $old $new")
        val newOld = cumulativeProbabilities[id]!!/nodes[id]!!
//        println("$id:$newOld $old -> $new")
        if(id in unions){
            cumulativeProbabilities[id] = if (reverseEdges[id]!!.isEmpty()) 0.0 else 1.0
            for(node in reverseEdges[id]!!){
                cumulativeProbabilities[id] = cumulativeProbabilities[id]!! * cumulativeProbabilities[node]!!
            }
        } else {
            val temp = (newOld - old)/(1 - old)
            cumulativeProbabilities[id] = temp + new + temp*new
        }
        cumulativeProbabilities[id] = cumulativeProbabilities[id]!! * nodes[id]!!
        for(node in this.edges[id]!!){
            reweigh(newOld*nodes[id]!!, cumulativeProbabilities[id]!!, node)
        }
    }

    fun removeEdge(from: K, to: K){
        if(from !in nodes.keys)
            throw IllegalArgumentException("$from not found in nodes")
        if(to !in nodes.keys)
            throw IllegalArgumentException("$to not found in nodes")
        if(to == from || to !in edges[from]!! || from !in reverseEdges[to]!!)
            throw IllegalArgumentException("Edge $from -> $to not found in graph")
        this.edges[from]!!.remove(to)
        this.reverseEdges[to]!!.remove(from)
        val oldIn = cumulativeProbabilities[to]!!/nodes[to]!!
        if(to in unions){
            if(reverseEdges[to]!!.isEmpty())
                cumulativeProbabilities[to] = 0.0
            else
                cumulativeProbabilities[to] = oldIn/cumulativeProbabilities[from]!!
        } else {
            cumulativeProbabilities[to] = oldIn - cumulativeProbabilities[from]!! + oldIn * cumulativeProbabilities[from]!!
        }
        cumulativeProbabilities[to] = cumulativeProbabilities[to]!! * nodes[to]!!
//        for(node in this.edges[to]!!){
//            reweigh(oldIn*nodes[to]!!, 0.0, node)
//        }
    }

    operator fun contains(id: K) = id in nodes.keys
}