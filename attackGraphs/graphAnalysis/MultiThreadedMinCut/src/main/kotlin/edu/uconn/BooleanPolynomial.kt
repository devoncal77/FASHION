package edu.uconn

import java.lang.StringBuilder

class BooleanPolynomial: Map<Set<String>, Double> {
    private val backingMap: Map<Set<String>, Double>
    constructor(backingMap: Map<Set<String>, Double> = mapOf()){
        this.backingMap = backingMap
    }

    constructor(i: Double){
        this.backingMap = mapOf(setOf<String>() to i)
    }

    constructor(s: String){
        this.backingMap = mapOf(setOf(s) to 1.0)
    }

    override val entries: Set<Map.Entry<Set<String>, Double>>
        get() = this.backingMap.entries
    override val keys: Set<Set<String>>
        get() = this.backingMap.keys
    override val size: Int
        get() = this.backingMap.size
    override val values: Collection<Double>
        get() = this.backingMap.values

    override fun containsKey(key: Set<String>)= backingMap.containsKey(key)

    override fun containsValue(value: Double) = backingMap.containsValue(value)

    override fun get(key: Set<String>): Double? = backingMap[key]

    override fun isEmpty(): Boolean = backingMap.isEmpty()

    operator fun unaryMinus(): BooleanPolynomial{
        return BooleanPolynomial(this.mapValues{-it.value})
    }

    operator fun plus(other: BooleanPolynomial): BooleanPolynomial{
        val out = HashMap<Set<String>, Double>(other)
        for ((k,v) in this.entries){
            if(k in out){
                out[k] = out[k]!! + v
            } else {
                out[k]=v
            }
        }
        return BooleanPolynomial(out)
    }

    operator fun plus(other: Double) = this + BooleanPolynomial(other)
    operator fun plus(other: String) = this + BooleanPolynomial(other)
    operator fun minus(other: BooleanPolynomial) = this + -other
    operator fun minus(other: Double) = this + - BooleanPolynomial(other)
    operator fun minus(other: String) = this + - BooleanPolynomial(other)

    operator fun times(other: BooleanPolynomial): BooleanPolynomial{
        val out = mutableMapOf<Set<String>, Double>()
        for((k,v) in this.entries){
            for((i, j) in other.entries){
                val monomial = k + i
                if(monomial in out){
                    out[monomial] = out[monomial]!! + v * j
                } else {
                    out[monomial] = v*j
                }
                if(out[monomial] == 0.0){
                    out.remove(monomial)
                }
            }
        }
        return BooleanPolynomial(out)
    }
    operator fun times(other: Double): BooleanPolynomial{
        if(other == 0.0){
            return BooleanPolynomial()
        }
        if(other == 1.0){
            return this
        }
        return BooleanPolynomial(this.mapValues{other * it.value})
    }
    operator fun times(other: String): BooleanPolynomial{
        val asSet = setOf(other)
        return BooleanPolynomial(this.mapKeys{it.key + asSet})
    }

    override fun toString(): String{
        val builder = StringBuilder()
        builder.append("(+ ")
        for((k,v) in this.entries){
            if(v == 1.0){
                builder.append("(* ")
                builder.append(k.joinToString(separator = " ") { it })
            }
            builder.append("(")
        }
        return "(+ " + this.asSequence().joinToString(separator = "\n   "){
            if(it.value == 1.0){
                "(* " + it.key.joinToString(separator = " ") + ")"
            }
            if(it.key.isEmpty()){
                it.value
            }
            "(* " + it.value + " " + it.key.joinToString(separator = " ") + ")"
        } + ")"
    }

}

operator fun Double.plus(other: BooleanPolynomial) =  other + this
operator fun Double.times(other: BooleanPolynomial)= other * this

operator fun String.plus(other: BooleanPolynomial) = other + this
operator fun String.times(other: BooleanPolynomial) = other * this
