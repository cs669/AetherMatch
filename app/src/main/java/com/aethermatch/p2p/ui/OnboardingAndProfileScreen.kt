package com.aethermatch.p2p.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Security
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import com.aethermatch.p2p.SystemDiagnosticsSnapshot
import com.aethermatch.p2p.model.RelationshipGoal
import com.aethermatch.p2p.model.UserProfile

private val SUGGESTED_INTERESTS = listOf(
    "Cryptography",
    "AI & ML",
    "Distributed Systems",
    "Climbing",
    "Trail Running",
    "Specialty Coffee",
    "Jazz & Vinyl",
    "Photography",
    "Cooking",
    "Philosophy",
    "Cycling",
    "Kayaking",
    "Sci-Fi",
    "Conservation",
    "Neuroscience",
    "Indie Art"
)

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun OnboardingAndProfileScreen(
    existingProfile: UserProfile?,
    diagnostics: SystemDiagnosticsSnapshot,
    onSaveProfile: (UserProfile) -> Unit
) {
    var displayName by remember(existingProfile) {
        mutableStateOf(existingProfile?.displayName ?: "")
    }
    var ageText by remember(existingProfile) {
        mutableStateOf(existingProfile?.age?.toString() ?: "28")
    }
    var bio by remember(existingProfile) {
        mutableStateOf(existingProfile?.bio ?: "")
    }
    var locationRegion by remember(existingProfile) {
        mutableStateOf(existingProfile?.locationRegion ?: "Metro Core")
    }
    var minAgeText by remember(existingProfile) {
        mutableStateOf(existingProfile?.preferredMinAge?.toString() ?: "23")
    }
    var maxAgeText by remember(existingProfile) {
        mutableStateOf(existingProfile?.preferredMaxAge?.toString() ?: "38")
    }
    var selectedGoal by remember(existingProfile) {
        mutableStateOf(existingProfile?.relationshipGoal ?: RelationshipGoal.LONG_TERM_PARTNER)
    }
    val selectedInterests = remember(existingProfile) {
        mutableStateListOf<String>().apply {
            addAll(existingProfile?.interests ?: listOf("Cryptography", "AI & ML", "Climbing", "Specialty Coffee"))
        }
    }
    var customInterest by remember { mutableStateOf("") }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        Text(
            text = if (existingProfile == null) "Create Decentralized Identity & Profile" else "Cryptographic Profile & Preferences",
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Bold,
            color = MaterialTheme.colorScheme.onBackground
        )

        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
            shape = RoundedCornerShape(12.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Icon(
                        imageVector = Icons.Default.Security,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary
                    )
                    Text(
                        text = "Zero-Server Ed25519 + Signal PQXDH Identity",
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.SemiBold
                    )
                }
                Text(
                    text = "libp2p PeerID: ${diagnostics.libp2p.peerId}",
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.primary
                )
                Text(
                    text = "Signal Identity FP: ${diagnostics.signal.identityKeyFingerprintHex}",
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    text = "Storage: ${diagnostics.sqlCipher.cipherVersion} • Keystore: ${diagnostics.keystore.providerName}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }

        OutlinedTextField(
            value = displayName,
            onValueChange = { displayName = it },
            label = { Text("Display Name") },
            placeholder = { Text("e.g., Jordan Rivera") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth()
        )

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            OutlinedTextField(
                value = ageText,
                onValueChange = { ageText = it.filter { ch -> ch.isDigit() } },
                label = { Text("Your Age") },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                singleLine = true,
                modifier = Modifier.weight(1f)
            )
            OutlinedTextField(
                value = locationRegion,
                onValueChange = { locationRegion = it },
                label = { Text("Region / Area") },
                singleLine = true,
                modifier = Modifier.weight(1.5f)
            )
        }

        OutlinedTextField(
            value = bio,
            onValueChange = { bio = it },
            label = { Text("About You (Used by Local AI Encoder)") },
            placeholder = { Text("Share your passions, projects, and what you value in a partner...") },
            minLines = 3,
            modifier = Modifier.fillMaxWidth()
        )

        Text(
            text = "Preferred Age Range",
            style = MaterialTheme.typography.titleSmall,
            fontWeight = FontWeight.SemiBold
        )
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            OutlinedTextField(
                value = minAgeText,
                onValueChange = { minAgeText = it.filter { ch -> ch.isDigit() } },
                label = { Text("Min Age") },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                singleLine = true,
                modifier = Modifier.weight(1f)
            )
            OutlinedTextField(
                value = maxAgeText,
                onValueChange = { maxAgeText = it.filter { ch -> ch.isDigit() } },
                label = { Text("Max Age") },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                singleLine = true,
                modifier = Modifier.weight(1f)
            )
        }

        Text(
            text = "Relationship Goal",
            style = MaterialTheme.typography.titleSmall,
            fontWeight = FontWeight.SemiBold
        )
        FlowRow(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            RelationshipGoal.entries.forEach { goal ->
                FilterChip(
                    selected = selectedGoal == goal,
                    onClick = { selectedGoal = goal },
                    label = { Text(goal.displayLabel) }
                )
            }
        }

        Text(
            text = "Passions & Interests (${selectedInterests.size} selected)",
            style = MaterialTheme.typography.titleSmall,
            fontWeight = FontWeight.SemiBold
        )
        FlowRow(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            val allTags = (SUGGESTED_INTERESTS + selectedInterests).distinct()
            allTags.forEach { tag ->
                val isSelected = tag in selectedInterests
                FilterChip(
                    selected = isSelected,
                    onClick = {
                        if (isSelected) selectedInterests.remove(tag) else selectedInterests.add(tag)
                    },
                    label = { Text(tag) }
                )
            }
        }

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            OutlinedTextField(
                value = customInterest,
                onValueChange = { customInterest = it },
                label = { Text("Add Custom Interest") },
                singleLine = true,
                modifier = Modifier.weight(1f)
            )
            OutlinedButton(
                onClick = {
                    val trimmed = customInterest.trim()
                    if (trimmed.isNotEmpty() && trimmed !in selectedInterests) {
                        selectedInterests.add(trimmed)
                        customInterest = ""
                    }
                }
            ) {
                Text("Add")
            }
        }

        val canSave = displayName.isNotBlank() && (ageText.toIntOrNull() ?: 0) >= 18 && selectedInterests.isNotEmpty()
        Button(
            onClick = {
                val age = (ageText.toIntOrNull() ?: 28).coerceIn(18, 99)
                val minAge = (minAgeText.toIntOrNull() ?: 21).coerceIn(18, 99)
                val maxAge = (maxAgeText.toIntOrNull() ?: 45).coerceAtLeast(minAge)
                onSaveProfile(
                    UserProfile(
                        peerId = diagnostics.libp2p.peerId,
                        displayName = displayName.trim(),
                        age = age,
                        bio = bio.trim().ifEmpty { "Exploring decentralized P2P connections." },
                        interests = selectedInterests.toList(),
                        relationshipGoal = selectedGoal,
                        locationRegion = locationRegion.trim().ifEmpty { "Global Mesh" },
                        preferredMinAge = minAge,
                        preferredMaxAge = maxAge
                    )
                )
            },
            enabled = canSave,
            modifier = Modifier.fillMaxWidth()
        ) {
            Icon(Icons.Default.Lock, contentDescription = null)
            Spacer(modifier = Modifier.padding(4.dp))
            Text("Sign with Ed25519 & Publish to Kademlia DHT")
        }

        if (existingProfile != null) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                Icon(
                    imageVector = Icons.Default.CheckCircle,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary
                )
                Text(
                    text = "Profile encrypted in SQLCipher & published with Signal Kyber-1024 PreKeyBundle.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.primary
                )
            }
        }
        Spacer(modifier = Modifier.height(24.dp))
    }
}
