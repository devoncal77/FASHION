package edu.uconn

fun main(args: Array<String>) {
    println("Hello, World")
    val test = BayesianNetwork("origin","root")
    for(i in 1..7)
        test.addNode("e$i", (i+1)/10.0)
    test.toggleUnion("root")

    test.addEdge("origin","e1")
    test.addEdge("origin","e2")
    test.addEdge("origin","e3")

    test.addEdge("e1","e4")
    test.addEdge("e2","e6")
    test.addEdge("e3","e5")
    test.addEdge("e4","e5")
    test.addEdge("e5","e7")
    test.addEdge("e6","root")
    test.addEdge("e7","root")
    println(test.cumulativeProbabilities)
    for(i in 1..7){
        val oldRoot = test.cumulativeProbabilities["root"]!!
        val from = "e$i"
        for(node in test.edges[from]!!){
            test.removeEdge(from, node)
            println("$oldRoot")
//            println("Removed $from -> $node. $oldRoot -> ${test.cumulativeProbabilities["root"]!!} changed by: ${oldRoot-test.cumulativeProbabilities["root"]!!}")
//            println(test.cumulativeProbabilities)
            test.addEdge(from,node)
//            println(test.cumulativeProbabilities)
        }

    }
//    test.addEdge("e4","e7")
//    println(test.cumulativeProbabilities)
}

