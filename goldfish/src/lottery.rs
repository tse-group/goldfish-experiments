use crate::vrf::Scheme;

pub trait Lottery {
    type Pk;
    type Sk;
    type Ticket;
    type Opening;

    fn open(&self, sk: &Self::Sk, ticket: Self::Ticket) -> Self::Opening;
    fn is_winning(&self, pk: &Self::Pk, ticket: Self::Ticket, rho: &Self::Opening) -> bool;
    fn prio(rho: &Self::Opening) -> u64;
    fn success_probability(&self) -> f64;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VrfLottery<S> {
    tag: &'static [u8],
    thr: u64,
    vrfs_type: std::marker::PhantomData<S>,
}

impl<S: Scheme> VrfLottery<S> {
    pub const fn new(tag: &'static [u8], thr: u64) -> Self {
        Self {
            tag: tag,
            thr: thr,
            vrfs_type: std::marker::PhantomData,
        }
    }
}

impl<S: Scheme> Lottery for VrfLottery<S> {
    type Pk = S::Pk;
    type Sk = S::Sk;
    type Ticket = u64; // t
    type Opening = (u64, S::Pf); // (y, pi)

    fn open(&self, sk: &Self::Sk, ticket: Self::Ticket) -> Self::Opening {
        let mut x = self.tag.to_vec();
        x.append(&mut ticket.to_le_bytes().to_vec());
        let (y, pi) = S::eval(&sk, &x);
        (y, pi)
    }

    fn is_winning(&self, pk: &Self::Pk, ticket: Self::Ticket, rho: &Self::Opening) -> bool {
        let (y, pi) = rho;
        let mut x = self.tag.to_vec();
        x.append(&mut ticket.to_le_bytes().to_vec());
        *y <= self.thr && S::verify(&pk, &x, *y, &pi)
    }

    fn prio(rho: &Self::Opening) -> u64 {
        let (y, _pi) = rho;
        *y
    }

    fn success_probability(&self) -> f64 {
        (self.thr as f64) / (u64::MAX as f64)
    }
}
