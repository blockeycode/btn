package org.btn.supervisor

import org.btn.common.*
import org.btn.core.Block
import org.btn.core.NodeInstance

abstract class SupervisorNode: NodeInstance(){
    @ExperimentalStdlibApi
    fun sealBlock(block: Block){
        if(!block.verify())
            return

        val signedData = sign(privateKey, block.hashCode)
        val hash = hash(signedData)
        val precedingZeroCount = leadingZeroCount(hash)
        if(precedingZeroCount <= btnNetwork.sealPrecedingThreshold)
            return

        block.clerk.seal(signedData,publicKey)
    }
}