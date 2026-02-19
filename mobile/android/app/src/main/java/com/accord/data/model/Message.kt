package com.accord.data.model

data class Message(
    val id: String,
    val channelId: String,
    val authorId: String,
    val content: String,
    val timestamp: Long,
    val edited: Boolean = false,
    val encrypted: Boolean = true,
)
