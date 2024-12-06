use rand::Rng;

// Fonction de génération d'un UUID u16 aléatoire
pub fn generate_u16_uuid() -> u16 {
    rand::thread_rng().gen()
}
