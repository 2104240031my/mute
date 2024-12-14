# Mute: Multiple User-Stream Transport with Encryption

# mutable
# mute

Tspp に multiplexing と CipherSuites Nego と VLint あたりを足した感じのTLSのいい感じの代替として使えそうなやつ。 ConnIDもつかう。（マイグレーションできるように）ほぼQUIC on Streamやな。

マイグレーションするなら、明示的シーケンスが必要なのか...
あとre-ordaring機能も...
めんどくさいな

ワンチャンQUIC on Streams実装したほうが面白い説...?
結構仕様少なそうやし