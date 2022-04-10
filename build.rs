use windres::Build;

fn main() {
    Build::new().compile("powersaver.rc").unwrap();
}
