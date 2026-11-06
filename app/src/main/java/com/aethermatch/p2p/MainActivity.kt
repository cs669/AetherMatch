package com.aethermatch.p2p

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Chat
import androidx.compose.material.icons.filled.Explore
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.Person
import androidx.compose.material3.Badge
import androidx.compose.material3.BadgedBox
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.aethermatch.p2p.ui.AetherMatchTheme
import com.aethermatch.p2p.ui.AetherMatchViewModel
import com.aethermatch.p2p.ui.DistributedComputeAndCryptoScreen
import com.aethermatch.p2p.ui.MatchesAndChatScreen
import com.aethermatch.p2p.ui.OnboardingAndProfileScreen
import com.aethermatch.p2p.ui.SwipeDeckScreen

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val app = application as AetherMatchApplication

        setContent {
            AetherMatchTheme {
                val vm: AetherMatchViewModel = viewModel(
                    factory = AetherMatchViewModel.Factory(app.appContainer)
                )
                AetherMatchAppRoot(vm)
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AetherMatchAppRoot(vm: AetherMatchViewModel) {
    val localProfile by vm.localProfile.collectAsState()
    val discoveredProfiles by vm.discoveredProfiles.collectAsState()
    val matches by vm.matches.collectAsState()
    val federatedRounds by vm.federatedRounds.collectAsState()
    val chatMessagesByPeer by vm.chatMessagesByPeer.collectAsState()
    val selectedChatPeerId by vm.selectedChatPeerId.collectAsState()
    val diagnostics by vm.diagnostics.collectAsState()
    val statusMessage by vm.statusMessage.collectAsState()
    val untrainedSwipesCount by vm.untrainedSwipesCount.collectAsState()
    val totalSwipesCount by vm.totalSwipesCount.collectAsState()

    // Default to Profile Onboarding if user has not created their local profile yet
    var selectedTab by rememberSaveable {
        mutableIntStateOf(if (localProfile == null) 3 else 0)
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text(
                            text = "AetherMatch P2P",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            text = "Noise XX • Kademlia DHT • Signal PQXDH • SQLCipher",
                            style = MaterialTheme.typography.labelSmall,
                            fontFamily = FontFamily.Monospace,
                            color = MaterialTheme.colorScheme.primary
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface
                )
            )
        },
        bottomBar = {
            NavigationBar(containerColor = MaterialTheme.colorScheme.surface) {
                NavigationBarItem(
                    selected = selectedTab == 0,
                    onClick = { selectedTab = 0 },
                    icon = { Icon(Icons.Default.Explore, contentDescription = "Discover") },
                    label = { Text("Discover") }
                )
                NavigationBarItem(
                    selected = selectedTab == 1,
                    onClick = { selectedTab = 1 },
                    icon = {
                        BadgedBox(
                            badge = {
                                if (matches.isNotEmpty()) {
                                    Badge { Text(matches.size.toString()) }
                                }
                            }
                        ) {
                            Icon(Icons.AutoMirrored.Filled.Chat, contentDescription = "Matches")
                        }
                    },
                    label = { Text("E2EE Chat") }
                )
                NavigationBarItem(
                    selected = selectedTab == 2,
                    onClick = { selectedTab = 2 },
                    icon = { Icon(Icons.Default.Memory, contentDescription = "Compute") },
                    label = { Text("FL & Crypto") }
                )
                NavigationBarItem(
                    selected = selectedTab == 3,
                    onClick = { selectedTab = 3 },
                    icon = { Icon(Icons.Default.Person, contentDescription = "Profile") },
                    label = { Text("Identity") }
                )
            }
        }
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
        ) {
            if (statusMessage != null) {
                Surface(
                    color = MaterialTheme.colorScheme.primaryContainer,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 12.dp, vertical = 4.dp)
                    ) {
                        Text(
                            text = statusMessage.orEmpty(),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onPrimaryContainer,
                            modifier = Modifier
                                .align(Alignment.CenterStart)
                                .padding(end = 64.dp)
                        )
                        TextButton(
                            onClick = { vm.clearStatusBanner() },
                            modifier = Modifier.align(Alignment.CenterEnd)
                        ) {
                            Text("Dismiss")
                        }
                    }
                }
            }

            Box(modifier = Modifier.weight(1f)) {
                when (selectedTab) {
                    0 -> SwipeDeckScreen(
                        discoveredProfiles = discoveredProfiles,
                        totalSwipesCount = totalSwipesCount,
                        untrainedSwipesCount = untrainedSwipesCount,
                        onSwipe = { candidate, liked -> vm.swipeOnCandidate(candidate, liked) },
                        onConnectBootstrapMultiaddr = { addr -> vm.connectBootstrapPeer(addr) }
                    )
                    1 -> MatchesAndChatScreen(
                        localPeerId = diagnostics.libp2p.peerId,
                        matches = matches,
                        selectedPeerId = selectedChatPeerId,
                        chatMessagesByPeer = chatMessagesByPeer,
                        onSelectPeer = { peerId -> vm.selectChatPeer(peerId) },
                        onSendMessage = { peerId, text -> vm.sendChatMessage(peerId, text) }
                    )
                    2 -> DistributedComputeAndCryptoScreen(
                        diagnostics = diagnostics,
                        federatedRounds = federatedRounds,
                        totalSwipesCount = totalSwipesCount,
                        untrainedSwipesCount = untrainedSwipesCount,
                        personalWeights = vm.getPersonalWeightsSnapshot(),
                        sharedWeights = vm.getSharedWeightsSnapshot(),
                        onRunConstrainedRound = { vm.triggerFederatedTrainingRound(forceDebugOverride = false) },
                        onRunDebugOverrideRound = { vm.triggerFederatedTrainingRound(forceDebugOverride = true) },
                        onConnectBootstrapPeer = { addr -> vm.connectBootstrapPeer(addr) }
                    )
                    else -> OnboardingAndProfileScreen(
                        existingProfile = localProfile,
                        diagnostics = diagnostics,
                        onSaveProfile = { profile ->
                            vm.saveUserProfile(profile)
                            selectedTab = 0
                        }
                    )
                }
            }
        }
    }
}
