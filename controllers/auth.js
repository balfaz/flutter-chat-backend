const { response, Router } = require('express');
const bcrypt = require('bcryptjs');

const Usuario = require('../models/usuario');
const { generarJWT } = require('../helpers/jwt');
const jwt = require('../helpers/jwt');
const usuario = require('../models/usuario');

const crearUsuario = async (req, res = response) => {

    const { email, password } = req.body;

    try {
        //Busca email duplicada
        const existeEmail = await Usuario.findOne({ email });
        if (existeEmail) {
            return res.status(400).json({
                ok: false,
                msg: 'El correo ya esta registrado'
            });
        }

        const usuario = new Usuario(req.body);
        const salt = bcrypt.genSaltSync();
        usuario.password = bcrypt.hashSync(password, salt)

        await usuario.save();

        //Generar webToken
        const token = await generarJWT(usuario.id);

        res.json({
            ok: true,
            usuario,
            token
        });
    } catch (error) {
        console.log(error);
        res.status(500).json({
            ok: false,
            msg: 'Hable con el administrador'
        });
    }
}

const login = async (req, res) => {
    const { email, password } = req.body;

    try {
        const usuarioDb = await Usuario.findOne({ email });
        if (!usuarioDb) {
            return res.status(404).json({
                ok: false,
                msg: 'Email no encontrada'
            });
        }

        const validPsw = bcrypt.compareSync(password, usuarioDb.password);
        if (!validPsw) {
            return res.status(400).json({
                ok: false,
                msg: 'Password no encontrada'
            });
        }

        const token = await generarJWT(usuarioDb.id);
        res.json({
            ok: true,
            usuarioDb,
            token
        });

    } catch (error) {
        console.log(error);
        res.status(500).json({
            ok: false,
            msg: 'Error durante el login, consulte al administrador DB'
        })

    }
}

const renewToken = async (req, res = response) => {

    //const uid = Usuario.uid;
    const uid = req.uid;

    const newToken = await generarJWT(uid);

    const usuario = await Usuario.findById(uid);
    console.log('usuario trovato');

    if (!usuario) {
        return res.status(401).json({
            ok: false,
            msg: 'Problemi durante la generazione del token, contacta administrador DB'
        });
    } else {
        res.json({
            ok: true,
            usuario,
            newToken
        });
    }

    //TODO: const uid del usuario
    //generar nuevo jwt
    // obtener el usuario por el IUD

}

module.exports = {
    crearUsuario,
    login,
    renewToken
}