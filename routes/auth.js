const { Router, response } = require('express');
const { check } = require('express-validator');

const { crearUsuario, login, renewToken } = require('../controllers/auth');
const { validarCampos } = require('../middlewares/validar-campos');
const { validarJWT } = require('../middlewares/validar-jwt');

const router = Router();



router.post('/new', [
    check('nombre', 'El nombre es obligatorio').not().isEmpty(),
    validarCampos,
    check('email', 'Campo Email con formato non valido').isEmail(),
    validarCampos,
    check('password', 'Password necesaria para continuar').not().isEmpty(),
    validarCampos
], crearUsuario);

router.post('/', [
    check('email', 'Campo Email con formato non valido').isEmail(),
    check('password', 'Password necesaria para continuar').not().isEmpty(),
], login);

router.get('/renew', validarJWT, renewToken);

module.exports = router;