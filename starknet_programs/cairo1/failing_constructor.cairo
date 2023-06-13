#[contract]
mod FailingConstructor {
    #[constructor]
    fn constructor() {
        assert( 1 == 0 , 'Oops');
    }

}
