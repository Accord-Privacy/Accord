package com.accord.data.model

data class Node(
    val id: String,
    val name: String,
    val description: String = "",
    val iconUrl: String? = null,
    val ownerId: String,
    val memberCount: Int = 0,
    val categories: List<Category> = emptyList(),
)

data class Category(
    val id: String,
    val name: String,
    val position: Int = 0,
)
