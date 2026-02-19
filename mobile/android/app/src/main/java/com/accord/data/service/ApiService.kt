package com.accord.data.service

import com.accord.data.model.Channel
import com.accord.data.model.Message
import com.accord.data.model.Node
import com.accord.data.model.User
import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import okhttp3.Interceptor
import okhttp3.MultipartBody
import okhttp3.OkHttpClient
import okhttp3.RequestBody
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Response
import retrofit2.Retrofit
import retrofit2.converter.moshi.MoshiConverterFactory
import retrofit2.http.*
import java.security.cert.X509Certificate
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

// ── Response models ──────────────────────────────────────────────────

@JsonClass(generateAdapter = true)
data class HealthResponse(
    val status: String,
    val version: String? = null,
)

@JsonClass(generateAdapter = true)
data class RegisterRequest(
    @Json(name = "public_key") val publicKey: String,
    val password: String,
    @Json(name = "display_name") val displayName: String? = null,
    val username: String = "", // deprecated but kept for compat
)

@JsonClass(generateAdapter = true)
data class RegisterResponse(
    val token: String,
    @Json(name = "user_id") val userId: String,
)

@JsonClass(generateAdapter = true)
data class AuthRequest(
    @Json(name = "public_key") val publicKey: String,
    val password: String,
)

@JsonClass(generateAdapter = true)
data class AuthResponse(
    val token: String,
    @Json(name = "user_id") val userId: String,
)

@JsonClass(generateAdapter = true)
data class NodeResponse(
    val id: String,
    val name: String,
    val description: String? = null,
    @Json(name = "owner_id") val ownerId: String? = null,
    @Json(name = "icon_hash") val iconHash: String? = null,
)

@JsonClass(generateAdapter = true)
data class ChannelResponse(
    val id: String,
    val name: String,
    @Json(name = "channel_type") val channelType: String? = null,
    @Json(name = "node_id") val nodeId: String? = null,
    @Json(name = "category_id") val categoryId: String? = null,
    val position: Int = 0,
    val topic: String? = null,
)

@JsonClass(generateAdapter = true)
data class MessageResponse(
    val id: String,
    @Json(name = "sender_id") val senderId: String,
    @Json(name = "sender_public_key_hash") val senderPublicKeyHash: String? = null,
    @Json(name = "encrypted_payload") val encryptedPayload: String? = null,
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "edited_at") val editedAt: Long? = null,
    @Json(name = "reply_to") val replyTo: String? = null,
    @Json(name = "display_name") val displayName: String? = null,
    val content: String? = null,
    val timestamp: Long = 0,
    val reactions: List<ReactionInfo>? = null,
    @Json(name = "pinned_at") val pinnedAt: Long? = null,
    @Json(name = "pinned_by") val pinnedBy: String? = null,
)

@JsonClass(generateAdapter = true)
data class ReactionInfo(
    val emoji: String,
    val count: Int = 0,
    val users: List<String> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class MessagePaginationResponse(
    val messages: List<MessageResponse>,
    @Json(name = "has_more") val hasMore: Boolean = false,
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class MemberResponse(
    @Json(name = "user_id") val userId: String,
    @Json(name = "public_key_hash") val publicKeyHash: String? = null,
    val role: String? = null,
    @Json(name = "joined_at") val joinedAt: Long = 0,
    val profile: MemberProfile? = null,
    val user: UserResponse? = null,
)

@JsonClass(generateAdapter = true)
data class MemberProfile(
    @Json(name = "display_name") val displayName: String? = null,
    val bio: String? = null,
    @Json(name = "avatar_hash") val avatarHash: String? = null,
)

@JsonClass(generateAdapter = true)
data class UserResponse(
    val id: String,
    @Json(name = "public_key_hash") val publicKeyHash: String? = null,
    @Json(name = "display_name") val displayName: String? = null,
    @Json(name = "created_at") val createdAt: Long = 0,
)

@JsonClass(generateAdapter = true)
data class UserProfileResponse(
    @Json(name = "user_id") val userId: String? = null,
    @Json(name = "display_name") val displayName: String? = null,
    val bio: String? = null,
    @Json(name = "avatar_hash") val avatarHash: String? = null,
)

@JsonClass(generateAdapter = true)
data class UpdateProfileRequest(
    @Json(name = "display_name") val displayName: String? = null,
    val bio: String? = null,
)

@JsonClass(generateAdapter = true)
data class KeyBundleRequest(
    @Json(name = "identity_key") val identityKey: String,
    @Json(name = "signed_prekey") val signedPrekey: String,
    @Json(name = "one_time_prekeys") val oneTimePrekeys: List<String> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class KeyBundleResponse(
    @Json(name = "identity_key") val identityKey: String,
    @Json(name = "signed_prekey") val signedPrekey: String,
    @Json(name = "one_time_prekey") val oneTimePrekey: String? = null,
)

@JsonClass(generateAdapter = true)
data class InviteResponse(
    @Json(name = "invite_code") val inviteCode: String,
    @Json(name = "expires_at") val expiresAt: Long? = null,
)

@JsonClass(generateAdapter = true)
data class InviteListItem(
    val code: String,
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "max_uses") val maxUses: Int? = null,
    @Json(name = "expires_at") val expiresAt: Long? = null,
    val uses: Int = 0,
)

@JsonClass(generateAdapter = true)
data class InviteListResponse(
    val invites: List<InviteListItem>,
)

@JsonClass(generateAdapter = true)
data class DmChannelResponse(
    val id: String,
    @Json(name = "user1_id") val user1Id: String,
    @Json(name = "user2_id") val user2Id: String,
    @Json(name = "created_at") val createdAt: Long = 0,
)

@JsonClass(generateAdapter = true)
data class DmChannelsListResponse(
    val channels: List<DmChannelResponse> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class SearchResponse(
    val messages: List<MessageResponse> = emptyList(),
    @Json(name = "total_count") val totalCount: Int = 0,
)

@JsonClass(generateAdapter = true)
data class RoleResponse(
    val id: String,
    val name: String,
    val color: String? = null,
    val hoist: Boolean = false,
    val position: Int = 0,
    val permissions: Long = 0,
    val mentionable: Boolean = false,
)

@JsonClass(generateAdapter = true)
data class FileUploadResponse(
    @Json(name = "file_id") val fileId: String,
    val url: String? = null,
)

@JsonClass(generateAdapter = true)
data class SlowModeResponse(
    @Json(name = "channel_id") val channelId: String? = null,
    @Json(name = "slow_mode_seconds") val slowModeSeconds: Int = 0,
)

@JsonClass(generateAdapter = true)
data class BuildInfoResponse(
    @Json(name = "commit_hash") val commitHash: String? = null,
    val version: String? = null,
    @Json(name = "build_hash") val buildHash: String? = null,
    @Json(name = "build_timestamp") val buildTimestamp: String? = null,
    @Json(name = "target_triple") val targetTriple: String? = null,
)

// ── Retrofit API Interface ───────────────────────────────────────────

interface AccordApi {

    // ── Health ────────────────────────────────────────────────────────
    @GET("health")
    suspend fun health(): HealthResponse

    @GET("api/build-info")
    suspend fun buildInfo(): BuildInfoResponse

    // ── Auth ─────────────────────────────────────────────────────────
    @POST("register")
    suspend fun register(@Body body: RegisterRequest): RegisterResponse

    @POST("auth")
    suspend fun login(@Body body: AuthRequest): AuthResponse

    // ── Nodes ────────────────────────────────────────────────────────
    @GET("nodes")
    suspend fun getNodes(): List<NodeResponse>

    @POST("nodes")
    suspend fun createNode(@Body body: Map<String, String>): NodeResponse

    @GET("nodes/{id}")
    suspend fun getNode(@Path("id") nodeId: String): NodeResponse

    @PATCH("nodes/{id}")
    suspend fun updateNode(@Path("id") nodeId: String, @Body body: Map<String, String>): Response<Unit>

    @POST("nodes/{id}/join")
    suspend fun joinNode(@Path("id") nodeId: String): Response<Unit>

    @POST("nodes/{id}/leave")
    suspend fun leaveNode(@Path("id") nodeId: String): Response<Unit>

    @GET("nodes/{id}/members")
    suspend fun getNodeMembers(@Path("id") nodeId: String): Map<String, List<MemberResponse>>

    @DELETE("nodes/{id}/members/{userId}")
    suspend fun kickMember(
        @Path("id") nodeId: String,
        @Path("userId") userId: String,
    ): Response<Unit>

    // ── Channels ─────────────────────────────────────────────────────
    @GET("nodes/{id}/channels")
    suspend fun getNodeChannels(@Path("id") nodeId: String): List<ChannelResponse>

    @POST("nodes/{id}/channels")
    suspend fun createChannel(
        @Path("id") nodeId: String,
        @Body body: Map<String, String>,
    ): ChannelResponse

    @PATCH("channels/{id}")
    suspend fun updateChannel(
        @Path("id") channelId: String,
        @Body body: Map<String, @JvmSuppressWildcards Any>,
    ): Response<Unit>

    @DELETE("channels/{id}")
    suspend fun deleteChannel(@Path("id") channelId: String): Response<Unit>

    // ── Messages ─────────────────────────────────────────────────────
    @GET("channels/{id}/messages")
    suspend fun getChannelMessages(
        @Path("id") channelId: String,
        @Query("limit") limit: Int = 50,
        @Query("before") before: String? = null,
    ): MessagePaginationResponse

    @PATCH("messages/{id}")
    suspend fun editMessage(
        @Path("id") messageId: String,
        @Body body: Map<String, String>,
    ): Response<Unit>

    @DELETE("messages/{id}")
    suspend fun deleteMessage(@Path("id") messageId: String): Response<Unit>

    @POST("channels/{id}/read")
    suspend fun markChannelRead(
        @Path("id") channelId: String,
        @Body body: Map<String, String>,
    ): Response<Unit>

    // ── Search ───────────────────────────────────────────────────────
    @GET("nodes/{id}/search")
    suspend fun searchMessages(
        @Path("id") nodeId: String,
        @Query("q") query: String,
        @Query("channel_id") channelId: String? = null,
        @Query("author_id") authorId: String? = null,
        @Query("before") before: String? = null,
        @Query("after") after: String? = null,
        @Query("limit") limit: Int = 50,
    ): SearchResponse

    // ── Reactions ────────────────────────────────────────────────────
    @PUT("messages/{id}/reactions/{emoji}")
    suspend fun addReaction(
        @Path("id") messageId: String,
        @Path("emoji") emoji: String,
    ): Response<Unit>

    @DELETE("messages/{id}/reactions/{emoji}")
    suspend fun removeReaction(
        @Path("id") messageId: String,
        @Path("emoji") emoji: String,
    ): Response<Unit>

    @GET("messages/{id}/reactions")
    suspend fun getReactions(@Path("id") messageId: String): List<ReactionInfo>

    // ── Pins ─────────────────────────────────────────────────────────
    @PUT("messages/{id}/pin")
    suspend fun pinMessage(@Path("id") messageId: String): Response<Unit>

    @DELETE("messages/{id}/pin")
    suspend fun unpinMessage(@Path("id") messageId: String): Response<Unit>

    // ── Threads ──────────────────────────────────────────────────────
    @GET("channels/{id}/threads")
    suspend fun getChannelThreads(@Path("id") channelId: String): List<MessageResponse>

    @GET("messages/{id}/thread")
    suspend fun getMessageThread(@Path("id") messageId: String): MessagePaginationResponse

    // ── User Profiles ────────────────────────────────────────────────
    @GET("users/{id}/profile")
    suspend fun getUserProfile(@Path("id") userId: String): UserProfileResponse

    @PUT("users/me/profile")
    suspend fun updateProfile(@Body body: UpdateProfileRequest): UserProfileResponse

    // ── Node User Profiles ───────────────────────────────────────────
    @PUT("nodes/{id}/profile")
    suspend fun setNodeUserProfile(
        @Path("id") nodeId: String,
        @Body body: Map<String, String>,
    ): Response<Unit>

    @GET("nodes/{id}/profiles")
    suspend fun getNodeUserProfiles(@Path("id") nodeId: String): Map<String, List<MemberProfile>>

    // ── Keys (E2EE) ──────────────────────────────────────────────────
    @POST("keys/bundle")
    suspend fun publishKeyBundle(@Body body: KeyBundleRequest): Response<Unit>

    @GET("keys/bundle/{userId}")
    suspend fun fetchKeyBundle(@Path("userId") userId: String): KeyBundleResponse

    // ── Invites ──────────────────────────────────────────────────────
    @POST("nodes/{id}/invites")
    suspend fun createInvite(
        @Path("id") nodeId: String,
        @Body body: Map<String, @JvmSuppressWildcards Any>? = null,
    ): InviteResponse

    @GET("nodes/{id}/invites")
    suspend fun listInvites(@Path("id") nodeId: String): InviteListResponse

    @DELETE("invites/{id}")
    suspend fun revokeInvite(@Path("id") inviteId: String): Response<Unit>

    @POST("invites/{code}/join")
    suspend fun useInvite(@Path("code") code: String): NodeResponse

    // ── Bans ─────────────────────────────────────────────────────────
    @POST("nodes/{id}/bans")
    suspend fun banUser(@Path("id") nodeId: String, @Body body: Map<String, String>): Response<Unit>

    @HTTP(method = "DELETE", path = "nodes/{id}/bans", hasBody = true)
    suspend fun unbanUser(@Path("id") nodeId: String, @Body body: Map<String, String>): Response<Unit>

    @GET("nodes/{id}/bans")
    suspend fun listBans(@Path("id") nodeId: String): List<Map<String, Any>>

    @GET("nodes/{id}/ban-check")
    suspend fun banCheck(@Path("id") nodeId: String): Map<String, Any>

    // ── Roles ────────────────────────────────────────────────────────
    @GET("nodes/{id}/roles")
    suspend fun getRoles(@Path("id") nodeId: String): List<RoleResponse>

    @POST("nodes/{id}/roles")
    suspend fun createRole(
        @Path("id") nodeId: String,
        @Body body: Map<String, @JvmSuppressWildcards Any>,
    ): RoleResponse

    @PATCH("nodes/{id}/roles/{roleId}")
    suspend fun updateRole(
        @Path("id") nodeId: String,
        @Path("roleId") roleId: String,
        @Body body: Map<String, @JvmSuppressWildcards Any>,
    ): Response<Unit>

    @DELETE("nodes/{id}/roles/{roleId}")
    suspend fun deleteRole(
        @Path("id") nodeId: String,
        @Path("roleId") roleId: String,
    ): Response<Unit>

    @GET("nodes/{id}/members/{userId}/roles")
    suspend fun getMemberRoles(
        @Path("id") nodeId: String,
        @Path("userId") userId: String,
    ): List<RoleResponse>

    @PUT("nodes/{id}/members/{userId}/roles/{roleId}")
    suspend fun assignMemberRole(
        @Path("id") nodeId: String,
        @Path("userId") userId: String,
        @Path("roleId") roleId: String,
    ): Response<Unit>

    @DELETE("nodes/{id}/members/{userId}/roles/{roleId}")
    suspend fun removeMemberRole(
        @Path("id") nodeId: String,
        @Path("userId") userId: String,
        @Path("roleId") roleId: String,
    ): Response<Unit>

    // ── Categories ───────────────────────────────────────────────────
    @POST("nodes/{id}/categories")
    suspend fun createCategory(
        @Path("id") nodeId: String,
        @Body body: Map<String, String>,
    ): Response<Unit>

    @PATCH("categories/{id}")
    suspend fun updateCategory(
        @Path("id") categoryId: String,
        @Body body: Map<String, @JvmSuppressWildcards Any>,
    ): Response<Unit>

    @DELETE("categories/{id}")
    suspend fun deleteCategory(@Path("id") categoryId: String): Response<Unit>

    // ── DMs ──────────────────────────────────────────────────────────
    @POST("dm/{userId}")
    suspend fun createDmChannel(@Path("userId") userId: String): DmChannelResponse

    @GET("dm")
    suspend fun getDmChannels(): DmChannelsListResponse

    // ── Blocking ─────────────────────────────────────────────────────
    @POST("users/{id}/block")
    suspend fun blockUser(@Path("id") userId: String): Response<Unit>

    @DELETE("users/{id}/block")
    suspend fun unblockUser(@Path("id") userId: String): Response<Unit>

    @GET("api/blocked-users")
    suspend fun getBlockedUsers(): Map<String, List<Map<String, Any>>>

    // ── Friends ──────────────────────────────────────────────────────
    @POST("friends/request")
    suspend fun sendFriendRequest(@Body body: Map<String, String>): Response<Unit>

    @POST("friends/accept")
    suspend fun acceptFriendRequest(@Body body: Map<String, String>): Response<Unit>

    @POST("friends/reject")
    suspend fun rejectFriendRequest(@Body body: Map<String, String>): Response<Unit>

    @GET("friends")
    suspend fun listFriends(): List<Map<String, Any>>

    @GET("friends/requests")
    suspend fun listFriendRequests(): List<Map<String, Any>>

    @DELETE("friends/{userId}")
    suspend fun removeFriend(@Path("userId") userId: String): Response<Unit>

    // ── Files ────────────────────────────────────────────────────────
    @Multipart
    @POST("channels/{id}/files")
    suspend fun uploadFile(
        @Path("id") channelId: String,
        @Part file: MultipartBody.Part,
        @Part("filename") filename: RequestBody? = null,
    ): FileUploadResponse

    @GET("files/{id}")
    @Streaming
    suspend fun downloadFile(@Path("id") fileId: String): okhttp3.ResponseBody

    @GET("channels/{id}/files")
    suspend fun getChannelFiles(@Path("id") channelId: String): List<Map<String, Any>>

    @DELETE("files/{id}")
    suspend fun deleteFile(@Path("id") fileId: String): Response<Unit>

    // ── Slow Mode ────────────────────────────────────────────────────
    @GET("channels/{id}/slow-mode")
    suspend fun getSlowMode(@Path("id") channelId: String): SlowModeResponse

    @PUT("channels/{id}/slow-mode")
    suspend fun setSlowMode(
        @Path("id") channelId: String,
        @Body body: Map<String, Int>,
    ): Response<Unit>

    // ── Auto-Mod ─────────────────────────────────────────────────────
    @GET("nodes/{id}/auto-mod")
    suspend fun listAutoModWords(@Path("id") nodeId: String): List<Map<String, String>>

    @POST("nodes/{id}/auto-mod")
    suspend fun addAutoModWord(
        @Path("id") nodeId: String,
        @Body body: Map<String, String>,
    ): Response<Unit>

    @DELETE("nodes/{id}/auto-mod/{word}")
    suspend fun removeAutoModWord(
        @Path("id") nodeId: String,
        @Path("word") word: String,
    ): Response<Unit>

    // ── Presence ─────────────────────────────────────────────────────
    @GET("api/presence/{id}")
    suspend fun getNodePresence(@Path("id") nodeId: String): Map<String, List<Map<String, String>>>

    // ── Audit Log ────────────────────────────────────────────────────
    @GET("nodes/{id}/audit-log")
    suspend fun getNodeAuditLog(
        @Path("id") nodeId: String,
        @Query("limit") limit: Int = 50,
        @Query("before") before: String? = null,
        @Query("action") action: String? = null,
    ): List<Map<String, Any>>

    // ── Push Notifications ───────────────────────────────────────────
    @POST("push/register")
    suspend fun registerPushToken(@Body body: Map<String, String>): Response<Unit>

    @HTTP(method = "DELETE", path = "push/register", hasBody = true)
    suspend fun deregisterPushToken(@Body body: Map<String, String>): Response<Unit>
}

// ── Auth Interceptor ─────────────────────────────────────────────────

/**
 * OkHttp interceptor that injects the Bearer auth token into every request.
 * Token can be updated at runtime via [updateToken].
 */
class AuthInterceptor : Interceptor {
    @Volatile
    var token: String? = null

    override fun intercept(chain: Interceptor.Chain): okhttp3.Response {
        val original = chain.request()
        val t = token ?: return chain.proceed(original)
        val request = original.newBuilder()
            .header("Authorization", "Bearer $t")
            .build()
        return chain.proceed(request)
    }

    fun updateToken(newToken: String?) {
        token = newToken
    }
}

// ── API Service Factory ──────────────────────────────────────────────

/**
 * Factory for creating the API service with auth, TLS, timeouts, and connection pooling.
 */
object ApiService {
    private val moshi: Moshi = Moshi.Builder()
        .addLast(KotlinJsonAdapterFactory())
        .build()

    /**
     * Create an [AccordApi] instance pointing at the given relay base URL.
     *
     * @param baseUrl The relay HTTP base URL (e.g. "https://relay.example.com").
     * @param authInterceptor Shared [AuthInterceptor] so the token can be updated after login.
     * @param trustAllCerts If true, disables TLS verification (development only!).
     */
    fun create(
        baseUrl: String,
        authInterceptor: AuthInterceptor = AuthInterceptor(),
        trustAllCerts: Boolean = false,
    ): Pair<AccordApi, AuthInterceptor> {
        val logging = HttpLoggingInterceptor().apply {
            level = HttpLoggingInterceptor.Level.NONE // set to BODY for debug
        }

        val clientBuilder = OkHttpClient.Builder()
            .addInterceptor(authInterceptor)
            .addInterceptor(logging)
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .writeTimeout(30, TimeUnit.SECONDS)
            .retryOnConnectionFailure(true)

        if (trustAllCerts) {
            @Suppress("CustomX509TrustManager", "TrustAllX509TrustManager")
            val trustManager = object : X509TrustManager {
                override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
                override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
                override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
            }
            val sslContext = SSLContext.getInstance("TLS")
            sslContext.init(null, arrayOf<TrustManager>(trustManager), null)
            clientBuilder.sslSocketFactory(sslContext.socketFactory, trustManager)
            clientBuilder.hostnameVerifier { _, _ -> true }
        }

        val client = clientBuilder.build()

        val retrofit = Retrofit.Builder()
            .baseUrl(baseUrl.trimEnd('/') + "/")
            .client(client)
            .addConverterFactory(MoshiConverterFactory.create(moshi))
            .build()

        return retrofit.create(AccordApi::class.java) to authInterceptor
    }
}
